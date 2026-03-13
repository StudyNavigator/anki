// Copyright: Ankitects Pty Ltd and contributors
// License: GNU AGPL, version 3 or later; http://www.gnu.org/licenses/agpl.html

mod handlers;
mod logging;
mod media_manager;
mod routes;
mod user;

use std::collections::HashMap;
use std::future::Future;
use std::future::IntoFuture;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use axum_client_ip::ClientIpSource;
use hyper::StatusCode;
use snafu::ResultExt;
use snafu::Whatever;
use tokio::net::TcpListener;
use tracing::Span;

use crate::error;
use crate::sync::error::HttpResult;
use crate::sync::error::OrHttpErr;
use crate::sync::http_server::logging::with_logging_layer;
use crate::sync::http_server::routes::collection_sync_router;
use crate::sync::http_server::routes::health_check_handler;
use crate::sync::http_server::routes::media_sync_router;
use crate::sync::http_server::user::User;
use crate::sync::login::HostKeyRequest;
use crate::sync::login::HostKeyResponse;
use crate::sync::request::SyncRequest;
use crate::sync::request::MAXIMUM_SYNC_PAYLOAD_BYTES;
use crate::sync::response::SyncResponse;

pub struct SimpleServer {
    state: Mutex<SimpleServerInner>,
    http_client: reqwest::Client,
    auth_base_url: String,
    auth_secret: String,
    base_folder: PathBuf,
}

pub struct SimpleServerInner {
    /// hkey -> user_id
    hkey_map: HashMap<String, String>,
    /// user_id -> User
    users: HashMap<String, User>,
}

#[derive(serde::Deserialize, Debug)]
pub struct SyncServerConfig {
    #[serde(default = "default_host")]
    pub host: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_base", rename = "base")]
    pub base_folder: PathBuf,
    #[serde(default = "default_ip_header")]
    pub ip_header: ClientIpSource,
    pub auth_base_url: String,
    pub auth_secret: String,
}

fn default_host() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}

fn default_port() -> u16 {
    8080
}

fn default_base() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| panic!("Unable to determine home folder; please set SYNC_BASE"))
        .join(".syncserver")
}

pub fn default_ip_header() -> ClientIpSource {
    ClientIpSource::ConnectInfo
}

impl SimpleServer {
    pub(in crate::sync) async fn with_authenticated_user<F, I, O>(
        &self,
        req: SyncRequest<I>,
        op: F,
    ) -> HttpResult<O>
    where
        F: FnOnce(&mut User, SyncRequest<I>) -> HttpResult<O>,
    {
        let hkey = req.sync_key.clone();

        // Check cache without holding the lock across an await point.
        let cached_user_id = self.state.lock().unwrap().hkey_map.get(&hkey).cloned();

        let user_id = if let Some(id) = cached_user_id {
            id
        } else {
            let id = self
                .verify_hkey(&hkey)
                .await
                .or_forbidden("invalid or expired token")?;
            let mut state = self.state.lock().unwrap();
            // Remove any stale hkeys that pointed to the same user.
            state.hkey_map.retain(|_, v| v != &id);
            // Create the User entry if this is a first-ever login for this user_id.
            if !state.users.contains_key(&id) {
                let user = User::new(&id, &self.base_folder)
                    .ok()
                    .or_internal_err("creating user")?;
                state.users.insert(id.clone(), user);
            }
            state.hkey_map.insert(hkey.clone(), id.clone());
            id
        };

        let mut state = self.state.lock().unwrap();
        let user = state
            .users
            .get_mut(&user_id)
            .or_internal_err("fetching user")?;
        Span::current().record("uid", &user.name);
        Span::current().record("client", &req.client_version);
        Span::current().record("session", &req.session_key);
        op(user, req)
    }

    async fn verify_hkey(&self, hkey: &str) -> Option<String> {
        #[derive(serde::Deserialize)]
        struct VerifyResponse {
            user_id: String,
        }

        let resp = self
            .http_client
            .get(format!("{}/internal/sync/verify", self.auth_base_url))
            .header("Authorization", format!("Bearer {hkey}"))
            .header("X-Internal-Secret", &self.auth_secret)
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            return None;
        }

        resp.json::<VerifyResponse>().await.ok().map(|r| r.user_id)
    }

    pub(in crate::sync) async fn get_host_key(
        &self,
        request: HostKeyRequest,
    ) -> HttpResult<SyncResponse<HostKeyResponse>> {
        #[derive(serde::Serialize)]
        struct TokenRequest<'a> {
            username: &'a str,
            password: &'a str,
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            hkey: String,
        }

        let resp = self
            .http_client
            .post(format!("{}/internal/sync/token", self.auth_base_url))
            .header("X-Internal-Secret", &self.auth_secret)
            .json(&TokenRequest {
                username: &request.username,
                password: &request.password,
            })
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, "failed to contact auth server");
                e
            })
            .or_internal_err("failed to contact auth server")?;

        if !resp.status().is_success() {
            match resp.status() {
                StatusCode::UNAUTHORIZED => {
                    tracing::warn!(username = %request.username, status = %resp.status(), "failed login attempt");
                    return None.or_forbidden("invalid credentials");
                }
                s if s.is_server_error() => {
                    tracing::error!(username = %request.username, status = %s, "auth server error");
                    return None.or_internal_err("auth server error");
                }
                s => {
                    tracing::warn!(username = %request.username, status = %s, "unexpected response from auth server");
                    return None.or_internal_err("unexpected response from auth server");
                }
            }
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .ok()
            .or_internal_err("invalid response from auth server")?;

        SyncResponse::try_from_obj(HostKeyResponse {
            key: token_resp.hkey,
        })
        .or_internal_err("encoding response")
    }

    pub fn is_running() -> bool {
        let config = envy::prefixed("SYNC_")
            .from_env::<SyncServerConfig>()
            .unwrap();
        std::net::TcpStream::connect(format!("{}:{}", config.host, config.port)).is_ok()
    }

    pub fn new(
        base_folder: &Path,
        auth_base_url: String,
        auth_secret: String,
    ) -> error::Result<Self, Whatever> {
        let http_client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .whatever_context("building HTTP client")?;
        Ok(SimpleServer {
            state: Mutex::new(SimpleServerInner {
                hkey_map: HashMap::new(),
                users: HashMap::new(),
            }),
            http_client,
            auth_base_url,
            auth_secret,
            base_folder: base_folder.to_path_buf(),
        })
    }

    pub async fn make_server(
        config: SyncServerConfig,
    ) -> error::Result<(SocketAddr, ServerFuture), Whatever> {
        let server = Arc::new(
            SimpleServer::new(
                &config.base_folder,
                config.auth_base_url,
                config.auth_secret,
            )
            .whatever_context("unable to create server")?,
        );
        let address = &format!("{}:{}", config.host, config.port);
        let listener = TcpListener::bind(address)
            .await
            .with_whatever_context(|_| format!("couldn't bind to {address}"))?;
        let addr = listener.local_addr().unwrap();
        let server = with_logging_layer(
            Router::new()
                .nest("/sync", collection_sync_router())
                .nest("/msync", media_sync_router())
                .route("/health", get(health_check_handler))
                .with_state(server)
                .layer(DefaultBodyLimit::max(*MAXIMUM_SYNC_PAYLOAD_BYTES))
                .layer(config.ip_header.into_extension()),
        );
        let future = axum::serve(
            listener,
            server.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .into_future();
        tracing::info!(%addr, "listening");
        Ok((addr, Box::pin(future)))
    }

    #[snafu::report]
    #[tokio::main]
    pub async fn run() -> error::Result<(), Whatever> {
        let config = envy::prefixed("SYNC_")
            .from_env::<SyncServerConfig>()
            .whatever_context("reading SYNC_* env vars")?;
        let (_addr, server_fut) = SimpleServer::make_server(config).await?;
        server_fut.await.whatever_context("await server")?;
        Ok(())
    }
}

pub type ServerFuture = Pin<Box<dyn Future<Output = error::Result<(), std::io::Error>> + Send>>;

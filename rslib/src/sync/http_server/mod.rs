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
    api_url: String,
    api_secret: String,
    base_folder: PathBuf,
}

pub struct SimpleServerInner {
    /// hkey->user
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
    pub api_url: String,
    pub api_secret: String,
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
        let cached = self.state.lock().unwrap().users.contains_key(&hkey);

        if !cached {
            let id = self
                .verify_hkey(&hkey)
                .await
                .or_forbidden("invalid or expired token")?;
            let user = User::new(&id, &self.base_folder)
                .ok()
                .or_internal_err("creating user")?;
            self.state.lock().unwrap().users.insert(hkey.clone(), user);
        }

        let mut state = self.state.lock().unwrap();
        let user = state.users.get_mut(&hkey).unwrap();
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

        let resp = reqwest::Client::new()
            .get(format!("{}/internal/sync/verify", self.api_url))
            .header("Authorization", format!("Bearer {hkey}"))
            .header("X-Internal-Secret", &self.api_secret)
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

        let resp = reqwest::Client::new()
            .post(format!("{}/internal/sync/token", self.api_url))
            .header("X-Internal-Secret", &self.api_secret)
            .json(&TokenRequest {
                username: &request.username,
                password: &request.password,
            })
            .send()
            .await
            .ok()
            .or_forbidden("failed to contact auth server")?;

        if !resp.status().is_success() {
            println!("Failed login attempt for user {}", request.username);
            println!("Response status: {}", resp.status());
            println!("Response body: {}", resp.text().await.unwrap_or_default());
            return None.or_forbidden("invalid credentials");
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
        api_url: String,
        api_secret: String,
    ) -> error::Result<Self, Whatever> {
        Ok(SimpleServer {
            state: Mutex::new(SimpleServerInner {
                users: HashMap::new(),
            }),
            api_url,
            api_secret,
            base_folder: base_folder.to_path_buf(),
        })
    }

    pub async fn make_server(
        config: SyncServerConfig,
    ) -> error::Result<(SocketAddr, ServerFuture), Whatever> {
        let server = Arc::new(
            SimpleServer::new(&config.base_folder, config.api_url, config.api_secret)
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

use askama_axum::IntoResponse;
use async_session::{MemoryStore, Session, SessionStore};
use axum::extract::{FromRef, FromRequestParts, Query, State};
use axum::http::HeaderMap;
use axum::response::Redirect;
use axum::{async_trait, RequestPartsExt};
use axum::{routing::get, Router};
use axum_extra::typed_header::TypedHeaderRejectionReason;
use axum_extra::{headers, TypedHeader};
use axum_macros::debug_handler;
use dotenv::dotenv;
use http::header;
use http::request::Parts;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::header::{COOKIE, SET_COOKIE};
use serde::{Deserialize, Serialize};
use std::env;
use tokio::sync::broadcast;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod handlers {
    pub mod api;
    pub mod pages;
    pub mod ws;
}

use handlers::pages::{chat_handler, index_handler};
use handlers::ws::ws_handler;

static COOKIE_NAME: &str = "SESSION";
static SCOPE: &str = "identify";

#[derive(Clone)]
pub struct AppState {
    pub tx: broadcast::Sender<String>,
    pub store: MemoryStore,
    pub oauth_client: BasicClient,
}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        state.store.clone()
    }
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        state.oauth_client.clone()
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "htmx-chat=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let (tx, _rx) = broadcast::channel(100);
    let oauth_client = oauth_client();
    let store = MemoryStore::new();

    let app_state = AppState {
        tx,
        store,
        oauth_client,
    };

    let app = Router::new()
        .route("/", get(index_handler))
        .route("/auth/discord", get(discord_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/chat", get(chat_handler))
        .route("/ws", get(ws_handler))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

fn oauth_client() -> BasicClient {
    let client_id = env::var("CLIENT_ID").unwrap();
    let client_secret = env::var("CLIENT_SECRET").unwrap();
    let redirect_url = env::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://localhost:3000/auth/authorized".to_string());

    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| {
        "https://discord.com/api/oauth2/authorize?response_type=code".to_string()
    });

    let token_url = env::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://discord.com/api/oauth2/token".to_string());

    BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).unwrap(),
        Some(TokenUrl::new(token_url).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap())
}

async fn discord_auth(
    State(client): State<BasicClient>,
    State(store): State<MemoryStore>,
) -> impl IntoResponse {
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(SCOPE.to_string()))
        .url();

    let mut session = Session::new();
    session.insert("csrf_token", &_csrf_token).unwrap();

    let cookie = store.store_session(session).await.unwrap().unwrap();

    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to(auth_url.as_ref()))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct AuthRequest {
    code: String,
    state: String,
}

async fn login_authorized(
    Query(query): Query<AuthRequest>,
    State(store): State<MemoryStore>,
    State(oauth_client): State<BasicClient>,
) -> impl IntoResponse {
    let token = oauth_client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .unwrap();

    // Fetch user data from discord
    let client = reqwest::Client::new();
    let user_data: User = client
        .get("https://discordapp.com/api/users/@me")
        .bearer_auth(token.access_token().secret())
        .send()
        .await
        .unwrap()
        .json::<User>()
        .await
        .unwrap();

    // Create a new session filled with user data
    let mut session = Session::new();
    session.insert("user", &user_data).unwrap();

    // Store session and get corresponding cookie
    let cookie = store.store_session(session).await.unwrap().unwrap();

    // Build the cookie
    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to("/chat"))
}

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub avatar: Option<String>,
    pub username: String,
    pub discriminator: String,
}

#[derive(Debug)]
pub struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> axum::http::Response<axum::body::Body> {
        Redirect::temporary("/auth/discord").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {e}"),
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

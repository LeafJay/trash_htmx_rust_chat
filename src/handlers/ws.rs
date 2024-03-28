use crate::{AppState, User};

use askama::Template;
use askama_axum::IntoResponse;
use axum::extract::{
    ws::{Message, WebSocket},
    State, WebSocketUpgrade,
};
use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::broadcast;

#[derive(Template)]
#[template(path = "message.html")]
struct MessageTemplate {
    message: String,
}

pub async fn ws_handler(
    user: User,
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(user, socket, state))
}

async fn handle_socket(user: User, mut socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    let mut rx = state.tx.subscribe();

    // let msg = format!("a user joined.");
    // let msg = "a user joined.".to_string();
    // let _ = state.tx.send(msg);

    let mut send_task = tokio::spawn(async move {
        while let Ok(text) = rx.recv().await {
            let msg = MessageTemplate { message: format!("{}: {}", user.username, text)};
            if sender.send(Message::Text(msg.to_string())).await.is_err() {
                break;
            }
        }
    });

    let tx = state.tx.clone();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(Message::Text(text))) = receiver.next().await {
            let root: Value = serde_json::from_str(&text).unwrap();
            let message = root.get("message").unwrap().as_str().unwrap();
            let _ = tx.send(message.to_string());
        }
    });

    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    let msg = "a user left.".to_string();
    tracing::debug!("{msg}");
    let _ = state.tx.send(msg);
}

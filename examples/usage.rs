//! Usage example
#![allow(clippy::unwrap_used, forbidden_lint_groups)]
use std::net::SocketAddr;

use axum::{
    Form, Json, Router,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use axum_safe_path::SafePath;
use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct Payload {
    path: SafePath,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/path/{*path}", get(path))
        .route("/form", post(form))
        .route("/json", post(json));

    // Run the server
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    println!("✓ Example running at http://{addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("./index.html"))
}

async fn path(SafePath(path): SafePath) -> impl IntoResponse {
    format!("Path is accepted: {}", path.display())
}

async fn form(Form(payload): Form<Payload>) -> impl IntoResponse {
    format!("Form is accepted: {}", payload.path.0.display())
}

async fn json(Json(payload): Json<Payload>) -> impl IntoResponse {
    format!("JSON is accepted: {}", payload.path.0.display())
}

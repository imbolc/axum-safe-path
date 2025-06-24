#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use std::{
    error::Error,
    fmt,
    path::{self, Component, PathBuf},
};

use axum::{
    extract::{FromRequestParts, Path, rejection::PathRejection},
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};

const REJECTION_MESSAGE: &str = "Invalid path: possible traversal attack detected";

/// A traversal-safe path extractor for Axum.
///
/// This extractor wraps `axum::extract::Path` and rejects requests
/// containing path components like `..`, `/`, or `C:`, preventing
/// directory traversal attacks.
#[derive(Debug)]
pub struct SafePath(pub PathBuf);

/// Rejection type for [`SafePath`].
#[derive(Debug)]
pub enum SafePathRejection {
    /// Possible traversal attack detected
    TraversalAttack,
    /// The underlying [`Path`] extractor failed
    PathExtraction(PathRejection),
}

impl fmt::Display for SafePathRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraversalAttack => f.write_str(REJECTION_MESSAGE),
            Self::PathExtraction(err) => write!(f, "{err}"),
        }
    }
}

impl Error for SafePathRejection {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::TraversalAttack => None,
            Self::PathExtraction(err) => Some(err),
        }
    }
}

impl IntoResponse for SafePathRejection {
    fn into_response(self) -> Response {
        match self {
            Self::TraversalAttack => (StatusCode::BAD_REQUEST, REJECTION_MESSAGE).into_response(),
            Self::PathExtraction(inner) => inner.into_response(),
        }
    }
}

/// Checks if a path contains traversal-related components such as `..`, a root
/// directory, or a drive prefix.
fn is_traversal_attack(path: impl AsRef<path::Path>) -> bool {
    path.as_ref().components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::Prefix(_) | Component::RootDir
        )
    })
}

impl<S> FromRequestParts<S> for SafePath
where
    S: Send + Sync,
{
    type Rejection = SafePathRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::from_request_parts(parts, state)
            .await
            .map_err(SafePathRejection::PathExtraction)?;

        (!is_traversal_attack(&path))
            .then_some(Self(path))
            .ok_or(SafePathRejection::TraversalAttack)
    }
}

#[cfg(any(feature = "json", feature = "form"))]
impl<'de> serde::Deserialize<'de> for SafePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let path = PathBuf::deserialize(deserializer)?;

        if is_traversal_attack(&path) {
            Err(serde::de::Error::custom(REJECTION_MESSAGE))
        } else {
            Ok(Self(path))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_paths() {
        assert!(!is_traversal_attack(""));
        assert!(!is_traversal_attack("."));
        assert!(!is_traversal_attack("./foo/bar.txt"));
        assert!(!is_traversal_attack("a/b/c/d"));
        assert!(!is_traversal_attack("foo.txt"));
        assert!(!is_traversal_attack("foo/./bar.txt"));
        assert!(!is_traversal_attack("foo/bar.txt"));
    }

    #[test]
    fn invalid_parent_dir() {
        assert!(is_traversal_attack(".."));
        assert!(is_traversal_attack("../foo.txt"));
        assert!(is_traversal_attack("foo/../bar.txt"));
        assert!(is_traversal_attack("foo/bar/.."));
    }

    #[test]
    fn invalid_absolute_paths() {
        assert!(is_traversal_attack("/etc/passwd"));
        assert!(is_traversal_attack("/foo/bar.txt"));
    }

    #[test]
    #[cfg(windows)]
    fn invalid_windows_paths() {
        assert!(is_traversal_attack("C:\\Users\\Admin"));
        assert!(is_traversal_attack("\\Windows"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod path_integration_tests {
    use axum::{Router, routing::get};
    use axum_test::TestServer;

    use super::*;

    async fn handler(SafePath(path): SafePath) -> String {
        format!("Path: {}", path.display())
    }

    #[tokio::test]
    async fn successful_path() {
        let app = Router::new().route("/path/{*path}", get(handler));
        let server = TestServer::new(app).unwrap();

        let res = server.get("/path/foo/bar.txt").await;
        assert_eq!(res.status_code(), StatusCode::OK);
        assert_eq!(res.text(), "Path: foo/bar.txt");
    }

    #[tokio::test]
    async fn rejected_path() {
        let app = Router::new().route("/path/{*path}", get(handler));
        let server = TestServer::new(app).unwrap();

        let res = server.get("/path//etc/passwd").await;
        assert_eq!(res.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(res.text(), REJECTION_MESSAGE);
    }
}

#[cfg(all(test, feature = "json"))]
#[allow(clippy::unwrap_used, forbidden_lint_groups)]
mod json_integration_tests {
    use axum::{Json, Router, routing::post};
    use axum_test::TestServer;
    use serde_json::json;

    use super::*;

    #[derive(serde::Deserialize)]
    struct Payload {
        path: SafePath,
    }

    async fn json_handler(Json(payload): Json<Payload>) -> String {
        format!("Path: {}", payload.path.0.display())
    }

    #[tokio::test]
    async fn successful_json_path() {
        let app = Router::new().route("/", post(json_handler));
        let server = TestServer::new(app).unwrap();

        let res = server
            .post("/")
            .json(&json!({ "path": "foo/bar.txt" }))
            .await;

        assert_eq!(res.status_code(), StatusCode::OK);
        assert_eq!(res.text(), "Path: foo/bar.txt");
    }

    #[tokio::test]
    async fn rejected_json_path() {
        let app = Router::new().route("/", post(json_handler));
        let server = TestServer::new(app).unwrap();

        let res = server
            .post("/")
            .json(&json!({ "path": "../secret.txt" }))
            .await;

        assert_eq!(res.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(res.text().contains(REJECTION_MESSAGE));
    }
}

#[cfg(all(test, feature = "form"))]
#[allow(clippy::unwrap_used, forbidden_lint_groups)]
mod form_integration_tests {
    use axum::{Form, Router, routing::post};
    use axum_test::TestServer;

    use super::*;

    #[derive(serde::Deserialize)]
    struct Payload {
        path: SafePath,
    }

    #[derive(serde::Serialize)]
    struct TestPayload<'a> {
        path: &'a str,
    }

    async fn form_handler(Form(payload): Form<Payload>) -> String {
        format!("Path: {}", payload.path.0.display())
    }

    #[tokio::test]
    async fn successful_form_path() {
        let app = Router::new().route("/", post(form_handler));
        let server = TestServer::new(app).unwrap();

        let res = server
            .post("/")
            .form(&TestPayload {
                path: "foo/bar.txt",
            })
            .await;

        assert_eq!(res.status_code(), StatusCode::OK);
        assert_eq!(res.text(), "Path: foo/bar.txt");
    }

    #[tokio::test]
    async fn rejected_form_path() {
        let app = Router::new().route("/", post(form_handler));
        let server = TestServer::new(app).unwrap();

        let res = server
            .post("/")
            .form(&TestPayload {
                path: "../secret.txt",
            })
            .await;

        assert_eq!(res.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(res.text().contains(REJECTION_MESSAGE));
    }
}

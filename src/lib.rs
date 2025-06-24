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

/// A traversal-safe path extractor for Axum.
///
/// This extractor wraps `axum::extract::Path` and rejects requests
/// containing path components like `..`, `/`, or `C:`, preventing
/// directory traversal attacks.
#[derive(Debug)]
pub struct SafePath<T>(pub T);

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
            Self::TraversalAttack => {
                write!(f, "Invalid path: possible traversal attack detected")
            }
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
            Self::TraversalAttack => (StatusCode::BAD_REQUEST, self.to_string()).into_response(),
            Self::PathExtraction(inner) => inner.into_response(),
        }
    }
}

/// Checks if a path contains components that could be used for traversal
/// attacks.
fn is_traversal_attack(path: impl AsRef<path::Path>) -> bool {
    path.as_ref()
        .components()
        .any(|c| !matches!(c, Component::CurDir | Component::Normal(_)))
}

impl<S> FromRequestParts<S> for SafePath<PathBuf>
where
    S: Send + Sync,
{
    type Rejection = SafePathRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(path) = Path::<PathBuf>::from_request_parts(parts, state)
            .await
            .map_err(SafePathRejection::PathExtraction)?;

        if is_traversal_attack(&path) {
            Err(SafePathRejection::TraversalAttack)
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
        assert!(is_traversal_attack("C:\\Users\\Admin"),);
        assert!(is_traversal_attack("\\Windows"),);
    }
}

# axum-safe-path

[![License](https://img.shields.io/crates/l/axum-safe-path.svg)](https://choosealicense.com/licenses/mit/)
[![Crates.io](https://img.shields.io/crates/v/axum-safe-path.svg)](https://crates.io/crates/axum-safe-path)
[![Docs.rs](https://docs.rs/axum-safe-path/badge.svg)](https://docs.rs/axum-safe-path)

Traversal-safe version of the [`axum::extract::Path`]. Can be wrapped in
[`axum::Json`] or [`axum::Form`]. The usage is straightforward; here's an
[example][].

## Contributing

Please run [.pre-commit.sh] before sending a PR, it will check everything.

## License

This project is licensed under the [MIT license][license].

[.pre-commit.sh]:
  https://github.com/imbolc/axum-safe-path/blob/main/.pre-commit.sh
[example]: https://github.com/imbolc/axum-safe-path/blob/main/examples/usage.rs
[license]: https://github.com/imbolc/axum-safe-path/blob/main/LICENSE

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.4](https://github.com/nivek3/http-extract/compare/v0.1.3...v0.1.4) - 2026-10-24

### Added

- add validated proxy protocol and URL scheme extraction

### Other

- update author information and repository links to reflect new ownership
- update README with badge links and section icons for better visibility

## [0.1.3](https://github.com/nivek3/http-extract/compare/v0.1.2...v0.1.3) - 2026-08-11

### Fixed

- validate only Forwarded for values ([#9](https://github.com/nivek3/http-extract/pull/9))

### Other

- refresh project documentation ([#8](https://github.com/nivek3/http-extract/pull/8))

## [0.1.2](https://github.com/nivek3/http-extract/compare/v0.1.1...v0.1.2) - 2026-08-10

### Added

- add request socket address extractors ([#6](https://github.com/nivek3/http-extract/pull/6))

### Added

- Add request-extension helpers for directly stored `SocketAddr` values and their IP components.
- Add `extract_socket_ip` for Axum/direct socket-peer selection and
  `extract_proxy_client_ip` for proxy Header selection with peer fallback.

### Removed

- Remove the former out-of-band `extract_peer_address` and `extract_peer_ip(SocketAddr)` passthrough
  functions; callers with an out-of-band `SocketAddr` can use the value directly or call its
  `ip()` method. The new request-based `extract_socket_ip(&Request)` reads peer extensions.

## [0.1.1](https://github.com/nivek3/http-extract/releases/tag/v0.1.1) - 2026-08-10

### Changed

- Expose all public extraction APIs directly from the crate root.

### Removed

- Remove the former public field-family module paths in favor of the flat crate-root API.

## [0.1.0](https://github.com/nivek3/http-extract/releases/tag/v0.1.0) - 2026-08-10

### Added

- First stable release of the framework-independent HTTP request metadata extractors.
- Runnable Axum integration example.

### Changed

- Use absolute GitHub links for the extended documentation.
- Keep runnable examples while excluding repository integration tests from the published crate.

### Fixed

- Reject bracketed IPv6 values without a port and out-of-range socket ports in `X-Forwarded-For`.

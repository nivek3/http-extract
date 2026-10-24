# http-extract

### Extract the signal. Keep trust explicit.

Strict, synchronous HTTP request metadata extraction for Rust, built on
ordinary `http` types.

[![Crates.io](https://img.shields.io/crates/v/http-extract.svg)](https://crates.io/crates/http-extract)
[![Documentation](https://docs.rs/http-extract/badge.svg)](https://docs.rs/http-extract)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](#license)

[Guide](https://nivek3.github.io/http-extract/) ·
[API reference](https://docs.rs/http-extract) ·
[Features](https://github.com/nivek3/http-extract/blob/main/docs/features.md) ·
[Axum example](https://github.com/nivek3/http-extract/tree/main/examples/axum)

`http-extract` provides small, direct functions for reading request metadata.
The default API is framework-independent; an optional `axum` feature reads an
existing socket peer from `ConnectInfo<SocketAddr>`.

Its central rule is simple: **transport facts and Header assertions are not the
same thing**. Values from `Forwarded`, `X-Forwarded-*`, and provider-specific
client-IP fields remain raw and untrusted until the deployment establishes an
explicit proxy trust boundary.

## 🚀 Quick start

Default features enable all common extractor families:

```toml
[dependencies]
http-extract = "0.1"
```

Header functions contain the parsing logic. Matching Request functions are
convenience wrappers over `request.headers()`:

```rust
use http_extract::{HeaderName, Request, extract_single_header_text};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = HeaderName::from_static("x-example");
    let request = Request::builder()
        .uri("https://example.com/items")
        .header(name.clone(), "metadata")
        .body(())?;

    assert_eq!(
        extract_single_header_text(request.headers(), &name)?,
        Some("metadata")
    );

    Ok(())
}
```

Feature-specific Header and Request pairs follow the same direct shape. See the
[Features guide](https://github.com/nivek3/http-extract/blob/main/docs/features.md)
for the complete API families.

For a smaller dependency surface, disable defaults and select only what the
application uses:

```toml
[dependencies]
http-extract = { version = "0.1", default-features = false, features = [
  "authority",
  "content-type",
] }
```

## 🛡️ Trust is part of the input

```text
socket peer ──────────────────────── transport fact

Forwarded / X-Forwarded-* ───────── raw Header assertion
provider client-IP fields ───────── raw Header assertion
                                             │
                                             ▼
                              deployment-specific trust policy
```

| Source          | Library behavior                                               | Security meaning                                  |
| --------------- | -------------------------------------------------------------- | ------------------------------------------------- |
| Socket peer     | Read from the request extension supplied by the server adapter | Connection fact; identifies the immediate peer    |
| `Forwarded`     | Strict RFC 7239 `for=` IP-chain parsing                        | Untrusted until the proxy boundary is established |
| `X-Forwarded-*` | Strict parsing of common de facto fields                       | Untrusted Header assertion                        |
| Provider fields | One explicit extractor per supported field                     | Untrusted vendor assertion                        |

`extract_client_ip` checks Header sources in this order:

1. RFC 7239 `Forwarded`;
2. `X-Forwarded-For`;
3. `X-Real-IP`;
4. `CF-Connecting-IP`.

That order is a library convention, not an RFC-defined trust policy. If a
first-present source has an invalid supported value, extraction fails instead of
silently falling through. For `Forwarded`, parameters other than `for` are
ignored after quote-aware element splitting; their names and values are not
validated.
`extract_client_ip_with_headers` accepts an explicit ordered source list.

`extract_socket_ip` never reads Headers. `extract_proxy_client_ip` uses the
default Header order and falls back to the socket peer only when every supported
Header is absent; it does not authenticate a proxy.

Read the
[client IP trust boundary](https://github.com/nivek3/http-extract/blob/main/docs/trusted-proxies.md)
before using a Header-derived address for authorization, rate limiting, or
auditing.

## 🧩 Features

| Cargo feature       | What it adds                                            |
| ------------------- | ------------------------------------------------------- |
| `api-key`           | `X-API-Key`, then `Api-Key` extraction                  |
| `authority`         | URI authority and strict `Host` extraction              |
| `authorization`     | Raw Authorization and Bearer/Basic scheme routing       |
| `client-ip`         | Socket-peer helpers and default/custom Header selection |
| `client-ip-headers` | Common provider and proxy client-IP fields              |
| `content-type`      | Strict parsing into `mime::Mime`                        |
| `forwarded`         | `Forwarded` `for=` IP chains and raw `proto=` selection |
| `request-id`        | `X-Request-Id`, then `Request-Id` fallback              |
| `x-forwarded`       | `X-Forwarded-For` and `X-Forwarded-Proto` parsing       |
| `scheme`            | Best-effort URI / proxy URL scheme selection           |
| `axum`              | Optional `ConnectInfo<SocketAddr>` peer adapter         |

Default features include every row except `axum`. With no default features, the
crate-wide `Error` and generic Header helpers remain available. The normal
default dependency tree does not include Axum, Tower, Tokio, tracing, or
OpenTelemetry.

See the complete
[Features guide](https://github.com/nivek3/http-extract/blob/main/docs/features.md)
for exact functions, return types, and feature relationships.

## 🔐 Errors and sensitive values

Strict field extractors return `Ok(None)` for missing optional metadata.
Duplicate, non-text, and malformed fields return the crate-wide `Error` as
documented by each extractor. Errors identify the field and category, never
the raw value.

The `scheme` feature adds `extract_request_url_scheme`, a best-effort borrowed
selector with this order: URI scheme, raw first `X-Forwarded-Proto` field line,
then the first `Forwarded` `proto=` assertion. It preserves raw case, empty
values, and protocol lists; it does not validate a protocol chain or authenticate
a proxy. A non-text `X-Forwarded-Proto` value falls back to `Forwarded`, and
`Forwarded` extraction errors yield `None`. Use the existing validated
`extract_header_x_forwarded_proto` API when a normalized protocol chain is needed.

Authorization credentials and API keys are exposed only by their explicit
extractors. Do not log those values, cookies, request bodies, complete query
strings, or raw forwarding fields.

## 📚 Axum example

The runnable
[Axum example](https://github.com/nivek3/http-extract/tree/main/examples/axum)
demonstrates peer extraction, request metadata, client-IP selection, generic
error responses, and safe observable output:

```sh
cargo run --example axum-demo --features axum
```

Axum is an optional integration boundary, not part of the default library core.

## 📖 Compatibility and standards

- Rust 1.96.0 or newer;
- HTTP semantics from [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html);
- narrow `Forwarded` support from
  [RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html);
- lightweight Bearer and Basic scheme routing informed by
  [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1) and
  [RFC 7617](https://www.rfc-editor.org/rfc/rfc7617.html#section-2).

The crate extracts metadata; it is not a complete HTTP, proxy, or authentication
implementation. `X-Forwarded-*` and provider-specific fields are de facto or
vendor conventions, not IETF standards. See
[Standards and compatibility](https://github.com/nivek3/http-extract/blob/main/docs/standards.md)
for the exact support boundary.

## 📄 License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)); or
- MIT License ([LICENSE-MIT](LICENSE-MIT)).

at your option.

# Features

The crate declares Rust 1.96.0 as its compiler compatibility baseline. Default
features enable the complete common extraction API: `api-key`, `authority`,
`authorization`, `client-ip`, `client-ip-headers`, `content-type`, `forwarded`,
`request-id`, `x-forwarded`, and `scheme`.

Every extraction feature owns one field family. Header functions contain the
parsing implementation; matching Request functions delegate through
`request.headers()`. All public APIs are exposed from the crate root.

## Feature and API reference

| Cargo feature | Adds | Main APIs | Success value |
| --- | --- | --- | --- |
| `api-key` | `X-API-Key`, then `Api-Key` extraction | `extract_header_api_key`, `extract_request_api_key` | `Option<&str>` |
| `authority` | URI authority and strict `Host` extraction | `extract_header_authority`, `extract_request_authority` | `Option<Authority>` |
| `authorization` | Raw Authorization and Bearer/Basic scheme routing | `extract_*_authorization`, `extract_*_bearer_token`, `extract_*_basic_credentials` | `Option<&str>` |
| `axum` | Optional Axum `ConnectInfo<SocketAddr>` peer adapter | `extract_axum_socket_address`, `extract_axum_socket_ip` | `Option<SocketAddr>` or `Option<IpAddr>` |
| `client-ip` | Socket-peer helpers and default/custom Header selection | `extract_socket_ip`, `extract_client_ip`, `extract_client_ip_with_headers`, `extract_proxy_client_ip` | `Option<IpAddr>` |
| `client-ip-headers` | Common provider and proxy client-IP fields | one `extract_header_*` and `extract_request_*` pair per field | `Option<IpAddr>` |
| `content-type` | Strict Content-Type parsing and the optional `mime` dependency | `extract_header_content_type`, `extract_request_content_type` | `Option<Mime>` |
| `forwarded` | Strict `for=` IP chains and raw `proto=` selection | `extract_header_forwarded_for`, `extract_request_forwarded_for`, `extract_header_forwarded_proto`, `extract_request_forwarded_proto` | `Option<Vec<IpAddr>>` or `Option<&str>` |
| `request-id` | `X-Request-Id`, then `Request-Id` precedence | `extract_header_request_id`, `extract_request_request_id` | `Option<&str>` |
| `x-forwarded` | Raw `X-Forwarded-For` and `X-Forwarded-Proto` parsing | `extract_*_x_forwarded_for`, `extract_*_x_forwarded_proto` | `Option<Vec<IpAddr>>` or `Option<Vec<String>>` |
| `scheme` | Best-effort URI / raw proxy scheme selection | `extract_request_url_scheme` | `Option<&str>` directly, without a `Result` |

The crate-wide `Error` and generic `header` utilities remain available with no
default features. `header` includes the strict singular-field helpers and
`append_header_value`, which appends without replacing existing field lines.

## Client IP composition

`extract_request_socket_address` and `extract_request_socket_ip` read a
`SocketAddr` stored directly in request extensions. `extract_socket_ip` prefers
Axum `ConnectInfo<SocketAddr>` when the `axum` feature is enabled, then falls
back to the direct extension. None of these peer helpers inspect Headers.

`extract_client_ip` uses the documented default Header order, while
`extract_client_ip_with_headers` accepts an explicit ordered slice of
`ClientIpHeader` values. Both return raw, untrusted Header assertions.
`extract_proxy_client_ip` applies the default Header order and uses
`extract_socket_ip` only when every Header in `CLIENT_IP_HEADERS` is absent.

The non-default `axum` feature enables `client-ip`. Its
`extract_axum_socket_address` and `extract_axum_socket_ip` functions return
`None` when `ConnectInfo<SocketAddr>` is absent; they never fabricate a peer.

See the [client IP trust boundary](trusted-proxies.md) before using a
Header-derived address for authorization, rate limiting, or auditing.

## Feature relationships

`scheme` enables `forwarded` and `x-forwarded`. Its selector retains the URI
scheme first, then the raw first `X-Forwarded-Proto` value, then the first
`Forwarded` protocol assertion. It preserves empty/raw values and omits parsing
errors. `Forwarded` protocol selection accepts repeated field lines and respects
quoted delimiters; quotes are stripped but quoted pairs are not unescaped.
This raw metadata API does not replace the normalized `X-Forwarded-Proto` chain
parser or establish proxy trust.

`client-ip` enables `client-ip-headers`, `forwarded`, and `x-forwarded` because
its selectors use those parsing APIs. `content-type` enables the optional
`mime` dependency. The normal default dependency tree does not include Axum,
Tower, Tokio, tracing, or OpenTelemetry.

Enable the optional Axum adapter and runnable example explicitly:

```sh
cargo run --example axum-demo --features axum
```

Useful checks for consumers and contributors:

```sh
cargo check --no-default-features
cargo test --no-default-features --features authority,content-type,request-id
cargo test --no-default-features --features client-ip
cargo test --no-default-features --features client-ip-headers
```

This feature layout does not imply additional runtime compatibility. See
[Standards and compatibility](standards.md) for the protocol support boundary.

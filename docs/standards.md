# Standards and compatibility

`http-extract` implements narrow extraction behavior derived from the stable
RFC versions below. It does not claim complete HTTP, proxy, or authentication
protocol conformance.

## IETF standards used

- [HTTP Semantics, RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html):
  [Section 5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5) informs
  strict field handling;
  [Section 7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2) covers
  request authority and `Host`;
  [Section 8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3) covers
  `Content-Type`; and
  [Section 11](https://www.rfc-editor.org/rfc/rfc9110.html#section-11) supplies
  the Authorization framework context. The crate only extracts these fields;
  it is not a complete HTTP implementation and does not authenticate.
  Host extraction uses `http::uri::Authority` and additionally rejects userinfo
  and non-digit port text. The port grammar permits empty ports and is not
  limited to `u16`; URI authority selection retains its existing precedence
  without validating a lower-priority Host field.
- [Forwarded, RFC 7239](https://www.rfc-editor.org/rfc/rfc7239.html): support is
  based on the field structure in
  [Section 4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4), the
  [`for=` parameter in Section 5.2](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.2),
  and IP node forms from
  [Section 6.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1).
  `extract_header_forwarded_for` returns a continuous IP chain and rejects
  missing, unknown, obfuscated, or non-IP nodes instead of skipping them. It
  ignores parameters other than `for` after quote-aware element splitting
  without validating their names or values, and does not implement the full
  Forwarded object model. Parsing and Header-based selection do not establish
  trust; deployments must account for the
  [Section 8](https://www.rfc-editor.org/rfc/rfc7239.html#section-8) security
  considerations independently.
  The separate `extract_header_forwarded_proto` API selects the first
  `proto=` parameter across repeated field lines, respecting quoted delimiters
  and decoding quoted pairs. It validates URI-scheme syntax from
  [RFC 3986 Section 3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1),
  normalizes to lowercase, and rejects empty/invalid values and duplicate
  `proto` parameters in an inspected element. It does not require `for=` or
  validate other parameters. Later elements and field lines are not parsed for
  protocols after selection. The scheme registration requirement in
  [Section 5.4](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.4) is not
  checked, so this remains a subset rather than full RFC 7239 validation.
  The `scheme` feature prefers URI scheme, then the first protocol from the
  validated `X-Forwarded-Proto` chain, then this Forwarded assertion. This is
  library policy, not an RFC-defined proxy priority. The selector returns
  `Result<Option<String>, Error>` and falls back only when a source is absent;
  parsing errors are propagated.
- [Bearer Token Usage, RFC 6750 Section 2.1](https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1):
  the helper performs ASCII case-insensitive scheme routing and returns the raw
  credential substring. It does not validate a token or authenticate.
- [Basic Authentication, RFC 7617 Section 2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2):
  the helper performs ASCII case-insensitive scheme routing and returns the raw
  credential substring. It does not validate credentials, decode Base64, or
  authenticate.

## Non-standard fields

The following are common vendor or de facto fields, not IETF standards:

- `X-Forwarded-For` and `X-Forwarded-Proto`;
- `CF-Connecting-IP`;
- `CloudFront-Viewer-Address`;
- `Fly-Client-IP`;
- `True-Client-IP`;
- `X-Envoy-External-Address`;
- `X-Real-IP`.

Their APIs only parse raw assertions. Presence does not authenticate a proxy or
make a value suitable for access control, rate limiting, or audit use. See the
[client IP trust boundary](trusted-proxies.md) for deployment guidance.

## Rust and feature compatibility

The declared Rust baseline is Rust 1.96.0, matching `Cargo.toml`'s
`rust-version` and `rust-toolchain.toml`. This is a compiler compatibility
statement only; the core remains synchronous and framework-independent, and no
broader runtime compatibility is implied.

Default features enable all documented extraction API families. Consumers using
`default-features = false` can select only the features they need. The exact
feature list, dependency relationships, and copyable configuration are in
[Features](features.md).

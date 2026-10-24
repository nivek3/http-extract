//! Best-effort URL scheme selection for request metadata.

use http::Request;

use crate::{X_FORWARDED_PROTO, extract_header_forwarded_proto};

/// Select a borrowed URL scheme from the URI or raw proxy assertions.
///
/// The order is URI scheme, the first `X-Forwarded-Proto` field line if textual,
/// then the first `Forwarded` `proto=` assertion. A non-text first
/// `X-Forwarded-Proto` value falls back to `Forwarded`; a `Forwarded` extraction
/// error is omitted. Values remain raw: empty values, letter case, and complete
/// `X-Forwarded-Proto` comma-separated lists are preserved. This is a best-effort
/// metadata selector, not the validated protocol-chain API
/// [`crate::extract_header_x_forwarded_proto`]. It does not authenticate proxies.
///
/// ```
/// use http_extract::{Request, extract_request_url_scheme};
///
/// let request = Request::builder()
///     .uri("/items")
///     .header("forwarded", "for=192.0.2.1;proto=https")
///     .body(())
///     .unwrap();
/// assert_eq!(extract_request_url_scheme(&request), Some("https"));
/// ```
pub fn extract_request_url_scheme<B>(request: &Request<B>) -> Option<&str> {
    request
        .uri()
        .scheme_str()
        .or_else(|| {
            request
                .headers()
                .get(&X_FORWARDED_PROTO)
                .and_then(|value| value.to_str().ok())
        })
        .or_else(|| {
            extract_header_forwarded_proto(request.headers())
                .ok()
                .flatten()
        })
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, Request};

    use super::*;

    #[test]
    fn scheme_keeps_source_precedence_and_borrowed_raw_values() {
        for (uri, proto, expected) in [
            ("https://example.com/items", "http", "https"),
            ("/items", "http", "http"),
            ("/items", "HTTPS, http", "HTTPS, http"),
            ("/items", "", ""),
        ] {
            let request = Request::builder()
                .uri(uri)
                .header(&X_FORWARDED_PROTO, proto)
                .header("forwarded", "proto=https")
                .body(())
                .unwrap();
            assert_eq!(extract_request_url_scheme(&request), Some(expected));
        }
    }

    #[test]
    fn scheme_handles_repeated_lines_and_missing_or_invalid_values() {
        let mut request = Request::builder().uri("/items").body(()).unwrap();
        assert_eq!(extract_request_url_scheme(&request), None);
        request
            .headers_mut()
            .append("forwarded", HeaderValue::from_static("proto=https"));
        request
            .headers_mut()
            .append("forwarded", HeaderValue::from_static("proto=http"));
        assert_eq!(extract_request_url_scheme(&request), Some("https"));
        request.headers_mut().append(
            &X_FORWARDED_PROTO,
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
        assert_eq!(extract_request_url_scheme(&request), Some("https"));
        request
            .headers_mut()
            .insert(&X_FORWARDED_PROTO, HeaderValue::from_static("http"));
        request
            .headers_mut()
            .append(&X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        assert_eq!(extract_request_url_scheme(&request), Some("http"));
        request.headers_mut().remove(&X_FORWARDED_PROTO);
        request.headers_mut().insert(
            "forwarded",
            HeaderValue::from_static("proto=\"unterminated"),
        );
        assert_eq!(extract_request_url_scheme(&request), None);
    }
}

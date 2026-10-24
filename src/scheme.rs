//! URL scheme selection from URI and untrusted proxy assertions.

use http::Request;

use crate::{Error, extract_header_forwarded_proto, extract_header_x_forwarded_proto};

/// Select a URL scheme from the URI or syntactically validated proxy assertions.
///
/// The order is URI scheme, the first protocol in `X-Forwarded-Proto`, then the
/// first `Forwarded` `proto=` assertion. This order is library policy. Proxy
/// protocols are normalized to lowercase. All `X-Forwarded-Proto` field lines
/// and items are validated before selecting the first protocol. A malformed
/// source returns an error; only an absent source falls back. Lower-priority
/// sources are not inspected after selection. Missing metadata returns
/// `Ok(None)`. Scheme registration and proxy trust are not checked.
///
/// ```
/// use http_extract::{Request, extract_request_url_scheme};
///
/// let request = Request::builder()
///     .uri("/items")
///     .header("forwarded", "for=192.0.2.1;proto=https")
///     .body(())
///     .unwrap();
/// assert_eq!(extract_request_url_scheme(&request).unwrap().as_deref(), Some("https"));
/// ```
pub fn extract_request_url_scheme<B>(request: &Request<B>) -> Result<Option<String>, Error> {
    if let Some(scheme) = request.uri().scheme_str() {
        return Ok(Some(scheme.to_owned()));
    }
    if let Some(protocols) = extract_header_x_forwarded_proto(request.headers())? {
        return Ok(protocols.into_iter().next());
    }
    extract_header_forwarded_proto(request.headers())
}

#[cfg(test)]
mod tests {
    use http::{HeaderValue, Request};

    use crate::{FORWARDED, X_FORWARDED_PROTO};

    use super::*;

    #[test]
    fn scheme_selects_and_normalizes_one_protocol_in_source_order() {
        for (uri, proto, expected) in [
            ("https://example.com/items", "http", "https"),
            ("/items", "http", "http"),
            ("/items", "HTTPS, http", "https"),
            ("/items", "Web+TLS", "web+tls"),
        ] {
            let request = Request::builder()
                .uri(uri)
                .header(&X_FORWARDED_PROTO, proto)
                .header(&FORWARDED, "proto=http")
                .body(())
                .unwrap();
            assert_eq!(
                extract_request_url_scheme(&request).unwrap().as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn scheme_falls_back_only_when_sources_are_absent() {
        let mut request = Request::builder().uri("/items").body(()).unwrap();
        assert_eq!(extract_request_url_scheme(&request), Ok(None));
        request
            .headers_mut()
            .append(&FORWARDED, HeaderValue::from_static("for=192.0.2.1"));
        assert_eq!(extract_request_url_scheme(&request), Ok(None));
        request
            .headers_mut()
            .append(&FORWARDED, HeaderValue::from_static(r#"proto="h\ttps""#));
        assert_eq!(
            extract_request_url_scheme(&request).unwrap().as_deref(),
            Some("https")
        );
        request
            .headers_mut()
            .append(&X_FORWARDED_PROTO, HeaderValue::from_static("HTTP"));
        request
            .headers_mut()
            .append(&X_FORWARDED_PROTO, HeaderValue::from_static("https"));
        assert_eq!(
            extract_request_url_scheme(&request).unwrap().as_deref(),
            Some("http")
        );
    }

    #[test]
    fn scheme_propagates_invalid_x_forwarded_proto_without_fallback() {
        for value in [
            HeaderValue::from_bytes(&[0xff]).unwrap(),
            HeaderValue::from_static(""),
            HeaderValue::from_static("https, http_2"),
        ] {
            let request = Request::builder()
                .uri("/items")
                .header(&X_FORWARDED_PROTO, value)
                .header(&FORWARDED, "proto=https")
                .body(())
                .unwrap();
            assert_eq!(
                extract_request_url_scheme(&request),
                Err(Error::invalid_header(X_FORWARDED_PROTO))
            );
        }
        let mut request = Request::builder()
            .header(&X_FORWARDED_PROTO, "https")
            .body(())
            .unwrap();
        request
            .headers_mut()
            .append(&X_FORWARDED_PROTO, HeaderValue::from_static("http_2"));
        assert_eq!(
            extract_request_url_scheme(&request),
            Err(Error::invalid_header(X_FORWARDED_PROTO))
        );
    }

    #[test]
    fn scheme_propagates_invalid_forwarded_proto() {
        let request = Request::builder()
            .header(&FORWARDED, "proto=\"unterminated")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_url_scheme(&request),
            Err(Error::invalid_header(FORWARDED))
        );
    }

    #[test]
    fn scheme_does_not_inspect_lower_priority_sources() {
        let request = Request::builder()
            .uri("https://example.com/items")
            .header(
                &X_FORWARDED_PROTO,
                HeaderValue::from_bytes(&[0xff]).unwrap(),
            )
            .header(&FORWARDED, "proto=\"unterminated")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_url_scheme(&request).unwrap().as_deref(),
            Some("https")
        );
        let request = Request::builder()
            .header(&X_FORWARDED_PROTO, "https")
            .header(&FORWARDED, "proto=\"unterminated")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_url_scheme(&request).unwrap().as_deref(),
            Some("https")
        );
    }
}

//! Parsing of untrusted `X-Forwarded-*` header conventions.
//!
//! These fields are widely deployed de facto conventions, not IETF standards.
//! The functions here only parse raw assertions; they do not establish trust or
//! select an effective client IP or request scheme. RFC 7239 `Forwarded` is the
//! standardized alternative for forwarding information; see
//! [RFC 7239, Section 4].
//!
//! [RFC 7239, Section 4]: https://www.rfc-editor.org/rfc/rfc7239.html#section-4

use std::net::{IpAddr, SocketAddr};

use http::{HeaderMap, HeaderName, Request};

use crate::{Error, header::is_scheme};

/// The de facto, non-IETF `X-Forwarded-For` field name.
pub const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");

/// The de facto, non-IETF `X-Forwarded-Proto` field name.
pub const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");

/// Extract all `X-Forwarded-For` field lines as an untrusted asserted IP chain.
///
/// Addresses are returned in field order, from the remotest assertion to the
/// one nearest the server. A missing field returns `None`. Repeated field lines
/// are accepted in wire order, but a non-text line, empty comma-separated item,
/// or invalid IP/socket-address item returns an error. Values are syntactically
/// parsed only; no sender is authenticated and parsing does not make them
/// trustworthy. A feature-gated [`crate::extract_client_ip`] convenience can
/// select from this and other fields, but it does not authenticate the sender;
/// establish trust out-of-band before using the result for a security decision.
pub fn extract_header_x_forwarded_for(headers: &HeaderMap) -> Result<Option<Vec<IpAddr>>, Error> {
    extract_comma_values(headers, &X_FORWARDED_FOR, |value| {
        parse_ip(value, X_FORWARDED_FOR)
    })
}

/// Extract the untrusted `X-Forwarded-For` chain from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_x_forwarded_for`], preserving its missing, repeated-line,
/// and malformed-value behavior. The returned assertions remain untrusted.
pub fn extract_request_x_forwarded_for<B>(
    request: &Request<B>,
) -> Result<Option<Vec<IpAddr>>, Error> {
    extract_header_x_forwarded_for(request.headers())
}

/// Extract all `X-Forwarded-Proto` field lines as untrusted protocol tokens.
///
/// A missing field returns `None`. Repeated field lines are accepted in wire
/// order. Each comma-separated item must be a non-empty URI-scheme token;
/// non-text lines and invalid items return an error. Valid tokens are normalized
/// to lowercase. This performs syntax validation only: it does not authenticate
/// the sender, select an effective request scheme, or make the values trusted.
pub fn extract_header_x_forwarded_proto(headers: &HeaderMap) -> Result<Option<Vec<String>>, Error> {
    extract_comma_values(headers, &X_FORWARDED_PROTO, |value| {
        if is_scheme(value) {
            Ok(value.to_ascii_lowercase())
        } else {
            Err(Error::invalid_header(X_FORWARDED_PROTO))
        }
    })
}

/// Extract untrusted `X-Forwarded-Proto` tokens from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_x_forwarded_proto`], preserving its missing, repeated-line,
/// normalization, and malformed-value behavior. The returned assertions remain
/// untrusted.
pub fn extract_request_x_forwarded_proto<B>(
    request: &Request<B>,
) -> Result<Option<Vec<String>>, Error> {
    extract_header_x_forwarded_proto(request.headers())
}

/// Extract the rightmost `X-Forwarded-For` IP address from a header.
///
/// This reads `headers` and delegates to
/// [`extract_header_x_forwarded_for`], preserving its missing and strict error
/// behavior. It does not establish trust in the returned assertion.
pub fn extract_rightmost_x_forwarded_for(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    Ok(extract_header_x_forwarded_for(headers)?.and_then(|ips| ips.last().copied()))
}

/// Parse an IP address or socket address from a string.
fn parse_ip(value: &str, name: HeaderName) -> Result<IpAddr, Error> {
    if let Ok(address) = value.parse() {
        return Ok(address);
    }
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok(address.ip());
    }
    Err(Error::invalid_header(name))
}

/// Extract comma-separated values from a header.
fn extract_comma_values<T>(
    headers: &HeaderMap,
    name: &HeaderName,
    mut parse: impl FnMut(&str) -> Result<T, Error>,
) -> Result<Option<Vec<T>>, Error> {
    let mut output = Vec::new();
    let mut present = false;
    for value in headers.get_all(name) {
        present = true;
        let value = value
            .to_str()
            .map_err(|_| Error::invalid_header(name.clone()))?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(Error::invalid_header(name.clone()));
            }
            output.push(parse(item)?);
        }
    }
    Ok(present.then_some(output))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn extracts_x_forwarded_for_across_field_lines() {
        let mut headers = HeaderMap::new();
        headers.append(&X_FORWARDED_FOR, "192.0.2.1, 198.51.100.2".parse().unwrap());
        headers.append(&X_FORWARDED_FOR, "203.0.113.3".parse().unwrap());

        assert_eq!(
            extract_header_x_forwarded_for(&headers).unwrap().unwrap(),
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 3)),
            ]
        );
    }

    #[test]
    fn rejects_invalid_x_forwarded_for_values() {
        let mut headers = HeaderMap::new();
        for value in [
            "[2001:db8::1]",
            "[2001:db8::1]junk",
            "[2001:db8::1]:65536",
            "[2001:db8::1]:99999",
        ] {
            headers.insert(&X_FORWARDED_FOR, value.parse().unwrap());
            assert!(
                matches!(
                    extract_header_x_forwarded_for(&headers),
                    Err(Error::InvalidHeader { .. })
                ),
                "unexpectedly accepted {value:?}",
            );
        }

        headers.insert(&X_FORWARDED_FOR, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_x_forwarded_for(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn accepts_bracketed_ipv6_with_valid_port() {
        let mut headers = HeaderMap::new();
        headers.insert(&X_FORWARDED_FOR, "[2001:db8::1]:65535".parse().unwrap());
        assert_eq!(
            extract_header_x_forwarded_for(&headers).unwrap(),
            Some(vec!["2001:db8::1".parse().unwrap()]),
        );
    }

    #[test]
    fn extracts_and_normalizes_x_forwarded_proto() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_x_forwarded_proto(&headers).unwrap(), None);

        headers.append(&X_FORWARDED_PROTO, "HTTPS, Web+TLS".parse().unwrap());
        assert_eq!(
            extract_header_x_forwarded_proto(&headers).unwrap().unwrap(),
            vec!["https".to_owned(), "web+tls".to_owned()]
        );

        headers.insert(&X_FORWARDED_PROTO, "http_2".parse().unwrap());
        assert!(matches!(
            extract_header_x_forwarded_proto(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn request_entry_points_delegate_to_headers() {
        let request = Request::builder()
            .header(&X_FORWARDED_FOR, "192.0.2.1")
            .header(&X_FORWARDED_PROTO, "HTTPS")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_x_forwarded_for(&request).unwrap(),
            Some(vec!["192.0.2.1".parse().unwrap()])
        );
        assert_eq!(
            extract_request_x_forwarded_proto(&request).unwrap(),
            Some(vec!["https".to_owned()])
        );
    }
}

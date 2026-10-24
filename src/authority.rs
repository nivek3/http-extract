//! Request authority and `Host` field extraction.
//!
//! The request-target authority and the `Host` field are defined by
//! [RFC 9110, Section 7.2]. This module returns an already parsed
//! [`http::uri::Authority`] and does not perform DNS resolution, origin
//! authorization, or proxy trust decisions.
//!
//! [RFC 9110, Section 7.2]: https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2

use http::{HeaderMap, Request, header::HOST, uri::Authority};

use crate::{Error, header::extract_single_header_text};

/// Extract a strict, singular, syntactically valid `Host` authority.
///
/// A missing field returns `None`. Duplicate, non-text, and syntactically
/// invalid fields, including an empty value, userinfo, and non-digit ports,
/// return an error that does not contain the field value. This function reads
/// only the [`HeaderMap`]; it does
/// not inspect a request URI or determine whether the authority is trusted.
/// Port syntax follows RFC 3986: an empty port is allowed and numeric ports
/// are not restricted to the `u16` range.
pub fn extract_header_authority(headers: &HeaderMap) -> Result<Option<Authority>, Error> {
    extract_single_header_text(headers, &HOST)?
        .map(|value| {
            let authority = value
                .parse::<Authority>()
                .map_err(|_| Error::invalid_header(HOST))?;
            let suffix = &value[authority.host().len()..];
            if value.contains('@')
                || (!suffix.is_empty()
                    && !suffix
                        .strip_prefix(':')
                        .is_some_and(|port| port.bytes().all(|byte| byte.is_ascii_digit())))
            {
                return Err(Error::invalid_header(HOST));
            }
            Ok(authority)
        })
        .transpose()
}

/// Extract the authority from a complete request.
///
/// The already parsed URI authority takes precedence and is returned without
/// inspecting or validating `Host`. [`extract_header_authority`] is called only
/// when the URI has no authority, so its missing and error behavior applies only
/// to that fallback. If neither source is present, this function returns
/// `None`. The result is syntactically parsed but is not DNS-resolved or
/// authorized as an origin.
pub fn extract_request_authority<B>(request: &Request<B>) -> Result<Option<Authority>, Error> {
    if let Some(authority) = request.uri().authority() {
        return Ok(Some(authority.clone()));
    }
    extract_header_authority(request.headers())
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Request, header::HOST};

    use super::*;

    #[test]
    fn extracts_host_authority_only() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_authority(&headers).unwrap(), None);

        headers.insert(HOST, "example.com:8443".parse().unwrap());
        assert_eq!(
            extract_header_authority(&headers)
                .unwrap()
                .unwrap()
                .as_str(),
            "example.com:8443"
        );
    }

    #[test]
    fn host_authority_rejects_invalid_duplicate_and_non_text_fields() {
        let mut invalid = HeaderMap::new();
        invalid.insert(HOST, "not a valid authority".parse().unwrap());
        assert!(matches!(
            extract_header_authority(&invalid),
            Err(Error::InvalidHeader { .. })
        ));

        let mut duplicate = HeaderMap::new();
        duplicate.append(HOST, "one.example".parse().unwrap());
        duplicate.append(HOST, "two.example".parse().unwrap());
        assert!(matches!(
            extract_header_authority(&duplicate),
            Err(Error::DuplicateHeader { .. })
        ));

        let mut non_text = HeaderMap::new();
        non_text.insert(HOST, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_authority(&non_text),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn host_rejects_userinfo_and_non_digit_ports() {
        for value in [
            "user@example.com",
            "user:password@example.com:443",
            "example.com:service",
            "example.com:+443",
            "example.com:44x",
            "[2001:db8::1]:service",
            "[2001:db8::1]junk",
        ] {
            let request = Request::builder()
                .uri("/items")
                .header(HOST, value)
                .body(())
                .unwrap();
            assert_eq!(
                extract_header_authority(request.headers()),
                Err(Error::invalid_header(HOST)),
                "unexpectedly accepted {value:?}"
            );
            assert_eq!(
                extract_request_authority(&request),
                Err(Error::invalid_header(HOST))
            );
        }
    }

    #[test]
    fn host_accepts_digit_port_syntax_without_u16_conversion() {
        for value in [
            "example.com",
            "example.com:",
            "example.com:65536",
            "[2001:db8::1]",
            "[2001:db8::1]:",
            "[2001:db8::1]:8443",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(HOST, value.parse().unwrap());
            assert_eq!(
                extract_header_authority(&headers)
                    .unwrap()
                    .unwrap()
                    .as_str(),
                value
            );
        }
    }

    #[test]
    fn request_uri_authority_ignores_invalid_host() {
        let request = Request::builder()
            .uri("https://example.com/items")
            .header(HOST, "not a valid authority")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_authority(&request)
                .unwrap()
                .unwrap()
                .as_str(),
            "example.com"
        );
    }

    #[test]
    fn request_uri_authority_ignores_duplicate_host() {
        let mut request = Request::builder()
            .uri("https://example.com/items")
            .body(())
            .unwrap();
        request
            .headers_mut()
            .append(HOST, "one.example".parse().unwrap());
        request
            .headers_mut()
            .append(HOST, "two.example".parse().unwrap());

        assert_eq!(
            extract_request_authority(&request)
                .unwrap()
                .unwrap()
                .as_str(),
            "example.com"
        );
    }

    #[test]
    fn request_falls_back_to_host_without_uri_authority() {
        let request = Request::builder()
            .uri("/items")
            .header(HOST, "fallback.example:8443")
            .body(())
            .unwrap();

        assert_eq!(
            extract_request_authority(&request)
                .unwrap()
                .unwrap()
                .as_str(),
            "fallback.example:8443"
        );
    }

    #[test]
    fn request_without_uri_or_host_authority_returns_none() {
        let request = Request::builder().uri("/items").body(()).unwrap();

        assert_eq!(extract_request_authority(&request).unwrap(), None);
    }
}

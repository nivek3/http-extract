//! Extraction of untrusted client IP and protocol assertions from `Forwarded`.
//!
//! [`extract_header_forwarded_for`] implements the crate's deliberately narrow
//! use of the standardized field: every field element must contain a usable
//! `for=` IP address, and the resulting chain remains untrusted.
//! A feature-gated [`crate::extract_client_ip`] convenience can select from
//! this and other fields, but that selection does not establish trust.
//!
//! The field grammar is defined by [RFC 7239, Section 4], the `for` parameter
//! by [RFC 7239, Section 5.2], node identifiers by [RFC 7239, Section 6], and
//! the trust limitations by [RFC 7239, Section 8]. This crate implements only
//! the subset needed to produce a continuous IP chain, not the full RFC object
//! model. The separate protocol extractor decodes and validates scheme syntax and
//! accepts repeated field lines without requiring a continuous IP chain.
//!
//! [RFC 7239, Section 4]: https://www.rfc-editor.org/rfc/rfc7239.html#section-4
//! [RFC 7239, Section 5.2]: https://www.rfc-editor.org/rfc/rfc7239.html#section-5.2
//! [RFC 7239, Section 6]: https://www.rfc-editor.org/rfc/rfc7239.html#section-6
//! [RFC 7239, Section 8]: https://www.rfc-editor.org/rfc/rfc7239.html#section-8

use std::net::IpAddr;

use http::{HeaderMap, HeaderName, Request};

use crate::{
    Error,
    header::{extract_single_header_text, is_scheme},
};

/// The standardized `Forwarded` field name from [RFC 7239, Section 4].
///
/// [RFC 7239, Section 4]: https://www.rfc-editor.org/rfc/rfc7239.html#section-4
pub const FORWARDED: HeaderName = HeaderName::from_static("forwarded");

/// Extract the first `proto=` assertion from `Forwarded` field lines.
///
/// Field lines and elements are searched in wire order. Parameter names are
/// case-insensitive, quoted delimiters are respected, and quoted pairs are
/// decoded. The protocol must have URI-scheme syntax and is normalized to
/// lowercase. Registration of the scheme is not checked. Other parameters are
/// ignored; unlike the IP-chain extractor, this does not require a `for=` parameter.
/// Missing fields or parameters return `Ok(None)`. Non-text field lines and
/// malformed protocol values, unbalanced quotes, and duplicate `proto` parameters in an
/// inspected element return a value-redacting error.
/// Parsing does not establish proxy trust. After inspecting the selected
/// element, later elements and field lines are not parsed for protocols.
pub fn extract_header_forwarded_proto(headers: &HeaderMap) -> Result<Option<String>, Error> {
    for value in headers.get_all(&FORWARDED) {
        let value = value.to_str().map_err(|_| invalid())?;
        for element in split_quoted(value, ',')? {
            let mut proto = None;
            for parameter in split_quoted(element, ';')? {
                let parameter = trim_ows(parameter);
                let (name, value) = parameter.split_once('=').unwrap_or((parameter, ""));
                if trim_ows(name).eq_ignore_ascii_case("proto") {
                    if proto.is_some() {
                        return Err(invalid());
                    }
                    let (value, _) = parse_parameter_value(value)?;
                    if !is_scheme(&value) {
                        return Err(invalid());
                    }
                    proto = Some(value.to_ascii_lowercase());
                }
            }
            if proto.is_some() {
                return Ok(proto);
            }
        }
    }
    Ok(None)
}

/// Extract the first `Forwarded` protocol assertion from a request.
///
/// Delegates to [`extract_header_forwarded_proto`], preserving its ordering,
/// decoding, normalization, errors, and lack of proxy authentication.
pub fn extract_request_forwarded_proto<B>(request: &Request<B>) -> Result<Option<String>, Error> {
    extract_header_forwarded_proto(request.headers())
}

/// Extract RFC 7239 `Forwarded` `for=` values as an untrusted IP chain.
///
/// Addresses are returned in wire order, from the remotest assertion to the
/// one nearest the server. A missing field returns `None`; an empty field is
/// invalid. Parsing does not make any address trustworthy. This crate's strict
/// profile requires exactly one field line and exactly one usable IP `for=`
/// parameter in every element. Duplicate or non-text field lines, ambiguous
/// element boundaries, missing or duplicate `for` parameters, and unknown,
/// obfuscated, or non-IP `for` nodes return an error. They are never skipped
/// because doing so would change the chain's meaning. Parameters other than
/// `for` are ignored without validating their names or values. Establish an
/// out-of-band proxy trust policy before using the chain for a security
/// decision.
pub fn extract_header_forwarded_for(headers: &HeaderMap) -> Result<Option<Vec<IpAddr>>, Error> {
    extract_single_header_text(headers, &FORWARDED)?
        .map(parse_forwarded_for)
        .transpose()
}

/// Extract the untrusted `Forwarded` `for=` IP chain from a complete request.
///
/// This reads `request.headers()` and delegates to
/// [`extract_header_forwarded_for`], preserving its missing and strict error
/// behavior. It does not establish trust in the returned assertions.
pub fn extract_request_forwarded_for<B>(
    request: &Request<B>,
) -> Result<Option<Vec<IpAddr>>, Error> {
    extract_header_forwarded_for(request.headers())
}

/// Extract the rightmost `Forwarded` `for=` IP address from a header.
///
/// This reads `headers` and delegates to
/// [`extract_header_forwarded_for`], preserving its missing and strict error
/// behavior. It does not establish trust in the returned assertion.
pub fn extract_rightmost_forwarded(headers: &HeaderMap) -> Result<Option<IpAddr>, Error> {
    Ok(extract_header_forwarded_for(headers)?.and_then(|ips| ips.last().copied()))
}

fn parse_forwarded_for(value: &str) -> Result<Vec<IpAddr>, Error> {
    split_quoted(value, ',')?
        .into_iter()
        .map(parse_forwarded_element_for)
        .collect()
}

fn parse_forwarded_element_for(element: &str) -> Result<IpAddr, Error> {
    if trim_ows(element).is_empty() {
        return Err(invalid());
    }

    let mut forwarded_for = None;
    for parameter in split_quoted(element, ';')? {
        let parameter = trim_ows(parameter);
        if parameter.is_empty() {
            return Err(invalid());
        }
        let Some((name, value)) = parameter.split_once('=') else {
            continue;
        };
        if !trim_ows(name).eq_ignore_ascii_case("for") {
            continue;
        }
        if forwarded_for.is_some() {
            return Err(invalid());
        }

        let (value, quoted) = parse_parameter_value(value)?;
        forwarded_for = Some(parse_forwarded_node(&value, quoted)?);
    }

    forwarded_for.ok_or_else(invalid)
}

fn parse_forwarded_node(value: &str, quoted: bool) -> Result<IpAddr, Error> {
    if !quoted {
        return value
            .parse::<std::net::Ipv4Addr>()
            .map(IpAddr::V4)
            .map_err(|_| invalid());
    }

    if let Some(rest) = value.strip_prefix('[') {
        let (address, suffix) = rest.split_once(']').ok_or_else(invalid)?;
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').ok_or_else(invalid)?;
            validate_node_port(port)?;
        }
        return address
            .parse::<std::net::Ipv6Addr>()
            .map(IpAddr::V6)
            .map_err(|_| invalid());
    }

    let (address, port) = value
        .split_once(':')
        .map_or((value, None), |(address, port)| (address, Some(port)));
    if let Some(port) = port {
        validate_node_port(port)?;
    }
    address
        .parse::<std::net::Ipv4Addr>()
        .map(IpAddr::V4)
        .map_err(|_| invalid())
}

fn validate_node_port(value: &str) -> Result<(), Error> {
    let numeric =
        !value.is_empty() && value.len() <= 5 && value.bytes().all(|byte| byte.is_ascii_digit());
    let obfuscated =
        value.len() > 1 && value.starts_with('_') && value.bytes().all(is_obfuscated_byte);
    if numeric || obfuscated {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn split_quoted(value: &str, delimiter: char) -> Result<Vec<&str>, Error> {
    let mut output = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;

    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == delimiter {
            output.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if quoted || escaped {
        return Err(invalid());
    }
    output.push(&value[start..]);
    Ok(output)
}

fn parse_parameter_value(value: &str) -> Result<(String, bool), Error> {
    let value = trim_ows(value);
    if !value.starts_with('"') {
        if value.is_empty() || !value.bytes().all(is_token_byte) {
            return Err(invalid());
        }
        return Ok((value.to_owned(), false));
    }
    if value.len() < 2 || !value.ends_with('"') {
        return Err(invalid());
    }

    let mut output = String::with_capacity(value.len() - 2);
    let mut escaped = false;
    for character in value[1..value.len() - 1].chars() {
        if escaped {
            if !is_quoted_pair_character(character) {
                return Err(invalid());
            }
            output.push(character);
            escaped = false;
        } else if character == '\\' {
            escaped = true;
        } else if is_quoted_text_character(character) {
            output.push(character);
        } else {
            return Err(invalid());
        }
    }
    if escaped {
        return Err(invalid());
    }
    Ok((output, true))
}

fn trim_ows(value: &str) -> &str {
    value.trim_matches([' ', '\t'])
}

const fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

const fn is_obfuscated_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
}

const fn is_quoted_text_character(character: char) -> bool {
    matches!(character, '\t' | ' ' | '!' | '#'..='[' | ']'..='~')
}

const fn is_quoted_pair_character(character: char) -> bool {
    matches!(character, '\t' | ' '..='~')
}

const fn invalid() -> Error {
    Error::invalid_header(FORWARDED)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use http::{HeaderMap, HeaderValue};

    use super::*;

    #[test]
    fn forwarded_proto_reads_repeated_lines_and_quoted_parameters() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_header_forwarded_proto(&headers), Ok(None));
        headers.append(&FORWARDED, "for=192.0.2.1".parse().unwrap());
        assert_eq!(extract_header_forwarded_proto(&headers), Ok(None));
        headers.append(
            &FORWARDED,
            "ext=\"proto=http,;\";Proto=\"HTTPS\"".parse().unwrap(),
        );
        headers.append(&FORWARDED, "proto=http".parse().unwrap());
        assert_eq!(
            extract_header_forwarded_proto(&headers).unwrap().as_deref(),
            Some("https")
        );
        let request = Request::builder()
            .header(&FORWARDED, "proto=https")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_forwarded_proto(&request)
                .unwrap()
                .as_deref(),
            Some("https")
        );
    }

    #[test]
    fn forwarded_proto_rejects_invalid_text_and_unbalanced_quotes() {
        for value in [
            HeaderValue::from_bytes(&[0xff]).unwrap(),
            HeaderValue::from_static("proto=\"https"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&FORWARDED, value);
            assert!(matches!(
                extract_header_forwarded_proto(&headers),
                Err(Error::InvalidHeader { .. })
            ));
        }
    }

    #[test]
    fn forwarded_proto_decodes_and_validates_scheme_syntax() {
        for (value, expected) in [
            (r#"proto="h\ttps""#, "https"),
            ("proto=Web+TLS", "web+tls"),
            ("for=unknown;proto=https", "https"),
            ("proto=https, proto=http", "https"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&FORWARDED, value.parse().unwrap());
            assert_eq!(
                extract_header_forwarded_proto(&headers).unwrap().as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn forwarded_proto_rejects_empty_invalid_and_duplicate_protocols() {
        for value in [
            "proto=",
            "proto",
            r#"proto="""#,
            "proto=1https",
            "proto=http_2",
            r#"proto="https, http""#,
            r#"proto="https http""#,
            r#"proto="https"junk"#,
            r#"proto="https\""#,
            "proto=https;proto=http",
            "proto=https;PROTO=https",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&FORWARDED, value.parse().unwrap());
            assert_eq!(
                extract_header_forwarded_proto(&headers),
                Err(invalid()),
                "unexpectedly accepted {value:?}"
            );
        }
    }

    #[test]
    fn forwarded_proto_stops_after_the_selected_element() {
        let mut headers = HeaderMap::new();
        headers.append(&FORWARDED, "proto=https".parse().unwrap());
        headers.append(&FORWARDED, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert_eq!(
            extract_header_forwarded_proto(&headers).unwrap().as_deref(),
            Some("https")
        );
    }

    #[test]
    fn returns_none_when_forwarded_is_absent() {
        assert_eq!(
            extract_header_forwarded_for(&HeaderMap::new()).unwrap(),
            None
        );
    }

    #[test]
    fn extracts_every_for_ip_in_wire_order() {
        let mut headers = HeaderMap::new();
        headers.insert(
            &FORWARDED,
            "for=192.0.2.60;proto=https, For=\"[2001:db8:cafe::17]:4711\";by=_edge, for=\"198.51.100.4:_port\";ext=\"a,b;c\""
                .parse()
                .unwrap(),
        );

        assert_eq!(
            extract_header_forwarded_for(&headers).unwrap().unwrap(),
            vec![
                "192.0.2.60".parse::<IpAddr>().unwrap(),
                "2001:db8:cafe::17".parse::<IpAddr>().unwrap(),
                "198.51.100.4".parse::<IpAddr>().unwrap(),
            ]
        );
    }

    #[test]
    fn extracts_for_ip_without_parsing_other_parameters() {
        let mut headers = HeaderMap::new();
        headers.insert(
            &FORWARDED,
            "for=52.159.243.17;host=example.vercel.app;proto=https;sig=c2lnbmF0dXJlCg==;exp=1786417338"
                .parse()
                .unwrap(),
        );

        assert_eq!(
            extract_header_forwarded_for(&headers).unwrap().unwrap(),
            vec!["52.159.243.17".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn ignores_malformed_parameters_other_than_for() {
        for parameter in ["broken", "=value", "bad name=value", "proto="] {
            let mut headers = HeaderMap::new();
            headers.insert(
                &FORWARDED,
                format!("for=192.0.2.1;{parameter}").parse().unwrap(),
            );

            assert_eq!(
                extract_header_forwarded_for(&headers).unwrap().unwrap(),
                vec!["192.0.2.1".parse::<IpAddr>().unwrap()],
                "unexpectedly rejected {parameter:?}"
            );
        }
    }

    #[test]
    fn request_entry_point_delegates_to_headers() {
        let request = Request::builder()
            .header(&FORWARDED, "for=192.0.2.1")
            .body(())
            .unwrap();
        assert_eq!(
            extract_request_forwarded_for(&request).unwrap(),
            Some(vec!["192.0.2.1".parse().unwrap()])
        );
    }

    #[test]
    fn rejects_a_duplicate_or_non_text_field() {
        let mut headers = HeaderMap::new();
        headers.append(&FORWARDED, "for=192.0.2.1".parse().unwrap());
        headers.append(&FORWARDED, "for=198.51.100.2".parse().unwrap());
        assert!(matches!(
            extract_header_forwarded_for(&headers),
            Err(Error::DuplicateHeader { .. })
        ));

        headers.clear();
        headers.insert(&FORWARDED, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_header_forwarded_for(&headers),
            Err(Error::InvalidHeader { .. })
        ));
    }

    #[test]
    fn rejects_any_element_that_cannot_extend_a_continuous_ip_chain() {
        for value in [
            "",
            "for=192.0.2.1,",
            "for=192.0.2.1,,for=198.51.100.2",
            "proto=https",
            "for=unknown",
            "for=_hidden",
            "for=example.com",
            "for=192.0.2.1:443",
            "for=\"[not-an-ip]\"",
            "for=192.0.2.1;for=198.51.100.2",
            "for=192.0.2.1;proto=\"unterminated",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(&FORWARDED, value.parse().unwrap());
            assert!(
                matches!(
                    extract_header_forwarded_for(&headers),
                    Err(Error::InvalidHeader { .. })
                ),
                "unexpectedly accepted {value:?}"
            );
        }
    }
}

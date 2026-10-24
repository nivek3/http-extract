//! Strict building blocks for HTTP field maps.
//!
//! These helpers implement the field-line handling used by the higher-level
//! extractors. They deliberately do not combine repeated lines unless the
//! field-specific extractor owns that grammar. See [RFC 9110, Section 5]
//! for HTTP field semantics.
//!
//! [RFC 9110, Section 5]: https://www.rfc-editor.org/rfc/rfc9110.html#section-5

use http::{HeaderMap, HeaderName, HeaderValue};

use crate::Error;

#[cfg(any(feature = "forwarded", feature = "x-forwarded"))]
pub(crate) fn is_scheme(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Append one already validated field value without replacing existing values.
///
/// Existing values for `name` remain in the map and `value` is appended after
/// them. The return value is `true` when the map already contained at least one
/// value for `name`, and `false` when this call inserted its first value.
/// [`HeaderName`] and [`HeaderValue`] validate their own inputs before this
/// function is called, so appending is infallible. The helper does not inspect,
/// format, or log the value; callers must continue to treat credential-bearing
/// values as sensitive.
pub fn append_header_value(headers: &mut HeaderMap, name: HeaderName, value: HeaderValue) -> bool {
    headers.append(name, value)
}

/// Extract a field value only when the field has at most one field line.
///
/// A missing field returns `None`. More than one field line returns
/// [`Error::DuplicateHeader`]. The returned [`HeaderValue`] is otherwise raw:
/// this function performs no text decoding, syntax validation, authentication,
/// or logging. It does not combine repeated lines or split values on commas;
/// those operations are only valid for fields whose own grammar permits them.
pub fn extract_single_header_value<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a HeaderValue>, Error> {
    let mut values = headers.get_all(name).iter();
    let first = values.next();
    if values.next().is_some() {
        return Err(Error::duplicate_header(name.clone()));
    }
    Ok(first)
}

/// Extract a singular field as text without silently discarding invalid bytes.
///
/// A missing field returns `None`, duplicate field lines return
/// [`Error::DuplicateHeader`], and a value that cannot be represented as text
/// returns [`Error::InvalidHeader`]. Empty text is preserved as `Some("")`.
/// No field-specific syntax validation is performed. Returned text may contain
/// credentials or other sensitive data and must not be logged or echoed; errors
/// identify only the field name and error category, never the value.
pub fn extract_single_header_text<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, Error> {
    extract_single_header_value(headers, name)?
        .map(|value| {
            value
                .to_str()
                .map_err(|_| Error::invalid_header(name.clone()))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, header::USER_AGENT};

    use super::*;

    #[test]
    fn distinguishes_missing_invalid_and_duplicate() {
        let mut headers = HeaderMap::new();
        assert_eq!(extract_single_header_text(&headers, &USER_AGENT), Ok(None));

        headers.insert(USER_AGENT, HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(matches!(
            extract_single_header_text(&headers, &USER_AGENT),
            Err(Error::InvalidHeader { .. })
        ));

        headers.clear();
        headers.append(USER_AGENT, HeaderValue::from_static("one"));
        headers.append(USER_AGENT, HeaderValue::from_static("two"));
        assert!(matches!(
            extract_single_header_text(&headers, &USER_AGENT),
            Err(Error::DuplicateHeader { .. })
        ));
    }

    #[test]
    fn append_preserves_existing_values() {
        let mut headers = HeaderMap::new();
        let name = HeaderName::from_static("x-example");
        assert!(!append_header_value(
            &mut headers,
            name.clone(),
            HeaderValue::from_static("first"),
        ));
        assert!(append_header_value(
            &mut headers,
            name.clone(),
            HeaderValue::from_static("second"),
        ));
        assert_eq!(
            headers
                .get_all(name)
                .iter()
                .map(HeaderValue::to_str)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            vec!["first", "second"]
        );
    }
}

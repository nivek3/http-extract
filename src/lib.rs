//! Strict, trust-aware extraction of HTTP request metadata.
//!
//! This crate operates primarily on [`http`] types and does not require a web
//! framework, Tower, tracing, or OpenTelemetry. An opt-in `axum` feature adds
//! only transport-peer extraction from Axum request extensions. Forwarding
//! fields are never trusted implicitly.
//!
//! The crate root exposes small synchronous extractors for coherent field
//! responsibilities. Applications compose only the functions they need at
//! their framework boundary; this crate does not impose a request-context
//! aggregate or an asynchronous adapter. Cargo features gate field-specific
//! APIs; disabling default features leaves the shared Header helpers and
//! [`Error`] available, and enabling a feature exposes only its documented API
//! and dependencies.

#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(missing_docs, missing_debug_implementations)]

#[cfg(feature = "api-key")]
mod api_key;
#[cfg(feature = "authority")]
mod authority;
#[cfg(feature = "authorization")]
mod authorization;
#[cfg(feature = "client-ip")]
mod client_ip;
#[cfg(feature = "client-ip-headers")]
mod client_ip_headers;
#[cfg(feature = "content-type")]
mod content_type;
#[cfg(feature = "forwarded")]
mod forwarded;

mod header;

#[cfg(feature = "request-id")]
mod request_id;
#[cfg(feature = "scheme")]
mod scheme;
#[cfg(feature = "x-forwarded")]
mod x_forwarded;

mod error;

pub use error::*;
pub use header::*;

pub use http::{HeaderMap, HeaderName, HeaderValue, Request};

// re-export the features
#[cfg(feature = "api-key")]
pub use api_key::*;
#[cfg(feature = "authority")]
pub use authority::*;
#[cfg(feature = "authorization")]
pub use authorization::*;
#[cfg(feature = "client-ip")]
pub use client_ip::*;
#[cfg(feature = "client-ip-headers")]
pub use client_ip_headers::*;
#[cfg(feature = "content-type")]
pub use content_type::*;
#[cfg(feature = "forwarded")]
pub use forwarded::*;
#[cfg(feature = "request-id")]
pub use request_id::*;
#[cfg(feature = "scheme")]
pub use scheme::*;
#[cfg(feature = "x-forwarded")]
pub use x_forwarded::*;

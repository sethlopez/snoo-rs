use std::fmt::{Display, Formatter, Result as FmtResult};

use failure::{Backtrace, Context, Fail};
use hyper;
use serde_json;
use serde_urlencoded;

#[derive(Debug)]
pub struct SnooError {
    inner: Context<SnooErrorKind>,
}

impl SnooError {
    pub fn kind(&self) -> SnooErrorKind {
        *self.inner.get_context()
    }
}

impl Fail for SnooError {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl Display for SnooError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        Display::fmt(&self.inner, f)
    }
}

impl From<SnooErrorKind> for SnooError {
    fn from(kind: SnooErrorKind) -> SnooError {
        SnooError { inner: Context::new(kind) }
    }
}

impl From<Context<SnooErrorKind>> for SnooError {
    fn from(context_kind: Context<SnooErrorKind>) -> SnooError {
        SnooError { inner: context_kind }
    }
}

impl From<hyper::error::UriError> for SnooError {
    fn from(_: hyper::error::UriError) -> SnooError {
        SnooErrorKind::InvalidRequest.into()
    }
}

impl From<hyper::Error> for SnooError {
    fn from(_: hyper::Error) -> SnooError {
        SnooErrorKind::NetworkError.into()
    }
}

impl From<serde_json::Error> for SnooError {
    fn from(_: serde_json::Error) -> Self {
        SnooErrorKind::InvalidRequest.into()
    }
}

impl From<serde_urlencoded::ser::Error> for SnooError {
    fn from(_: serde_urlencoded::ser::Error) -> Self {
        SnooErrorKind::InvalidRequest.into()
    }
}

impl From<serde_urlencoded::de::Error> for SnooError {
    fn from(_: serde_urlencoded::de::Error) -> Self {
        SnooErrorKind::InvalidResponse.into()
    }
}

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum SnooErrorKind {
    #[fail(display = "bad credentials")]
    BadCredentials,
    #[fail(display = "bad request")]
    InvalidRequest,
    #[fail(display = "bad response")]
    InvalidResponse,
    #[fail(display = "forbidden")]
    Forbidden,
    #[fail(display = "unauthorized")]
    Unauthorized,
    #[fail(display = "unsuccessful response: {}", _0)]
    UnsuccessfulResponse(u16),
    #[fail(display = "network error")]
    NetworkError,
}

#[derive(Debug, Eq, Fail, PartialEq)]
pub enum SnooBuilderError {
    #[fail(display = "missing authentication flow")]
    MissingAuthenticationFlow,
    #[fail(display = "missing client_id")]
    MissingClientId,
    #[fail(display = "missing user agent")]
    MissingUserAgent,
    #[fail(display = "hyper error")]
    HyperError,
}

// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Errors

use core::fmt;
#[cfg(feature = "std")]
use std::error;

use crate::primitives::absolute_locktime::AbsLockTimeError;
use crate::primitives::relative_locktime::RelLockTimeError;

/// An error parsing a Miniscript object (policy, descriptor or miniscript)
/// from a string.
#[derive(Debug)]
pub enum ParseError {
    /// Invalid absolute locktime
    AbsoluteLockTime(AbsLockTimeError),
    /// Invalid relative locktime
    RelativeLockTime(RelLockTimeError),
    /// Invalid key
    InvalidKey,
    /// Invalid hash
    InvalidHash,
    /// Failed to parse a number.
    Num(crate::ParseNumError),
    /// Error parsing a string into an expression tree.
    Tree(crate::ParseTreeError),
}

impl From<crate::ParseNumError> for ParseError {
    fn from(e: crate::ParseNumError) -> Self { Self::Num(e) }
}

impl From<crate::ParseTreeError> for ParseError {
    fn from(e: crate::ParseTreeError) -> Self { Self::Tree(e) }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseError::AbsoluteLockTime(ref e) => e.fmt(f),
            ParseError::RelativeLockTime(ref e) => e.fmt(f),
            ParseError::InvalidKey => f.write_str("invalid key"),
            ParseError::InvalidHash => f.write_str("invalid hash"),
            ParseError::Num(ref e) => e.fmt(f),
            ParseError::Tree(ref e) => e.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for ParseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ParseError::AbsoluteLockTime(ref e) => Some(e),
            ParseError::RelativeLockTime(ref e) => Some(e),
            ParseError::InvalidKey | ParseError::InvalidHash => None,
            ParseError::Num(ref e) => Some(e),
            ParseError::Tree(ref e) => Some(e),
        }
    }
}

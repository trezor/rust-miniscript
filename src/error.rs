// Written in 2019 by Andrew Poelstra <apoelstra@wpsoftware.net>
// SPDX-License-Identifier: CC0-1.0

//! Errors

use crate::blanket_traits::StaticDebugAndDisplay;
use crate::primitives::absolute_locktime::AbsLockTimeError;
use crate::primitives::relative_locktime::RelLockTimeError;
use crate::Box;

/// An error parsing a Miniscript object (policy, descriptor or miniscript)
/// from a string.
pub enum ParseError {
    /// Invalid absolute locktime
    AbsoluteLockTime(AbsLockTimeError),
    /// Invalid relative locktime
    RelativeLockTime(RelLockTimeError),
    /// Failed to parse a public key or hash.
    ///
    /// Note that the error information is lost for nostd compatibility reasons. See
    /// <https://users.rust-lang.org/t/how-to-box-an-error-type-retaining-std-error-only-when-std-is-enabled/>.
    FromStr(Box<dyn StaticDebugAndDisplay>),
    /// Failed to parse a number.
    Num(crate::ParseNumError),
    /// Error parsing a string into an expression tree.
    Tree(crate::ParseTreeError),
}

impl ParseError {
    /// Boxes a `FromStr` error for a `Pk` (or associated types) into a `ParseError`
    pub(crate) fn box_from_str<E: StaticDebugAndDisplay>(e: E) -> Self {
        ParseError::FromStr(Box::new(e))
    }
}

impl From<crate::ParseNumError> for ParseError {
    fn from(e: crate::ParseNumError) -> Self { Self::Num(e) }
}

impl From<crate::ParseTreeError> for ParseError {
    fn from(e: crate::ParseTreeError) -> Self { Self::Tree(e) }
}

// SPDX-License-Identifier: CC0-1.0

//! Expression-related errors

use core::num;

use crate::descriptor::checksum;
use crate::prelude::*;
use crate::ThresholdError;

/// An error parsing an expression tree.
#[derive(PartialEq, Eq)]
pub enum ParseTreeError {
    /// Error validating the checksum or character set.
    Checksum(checksum::Error),
    /// Expression tree had depth exceeding our hard cap.
    MaxRecursionDepthExceeded {
        /// The depth of the tree that was attempted to be parsed.
        actual: usize,
        /// The maximum depth.
        maximum: u32,
    },
    /// After a close-paren, the only valid next characters are close-parens and commas. Got
    /// something else.
    ExpectedParenOrComma {
        /// What we got instead.
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// An open-parenthesis had no corresponding close-parenthesis.
    UnmatchedOpenParen {
        /// The character in question ('(' or '{')
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// A close-parenthesis had no corresponding open-parenthesis.
    UnmatchedCloseParen {
        /// The character in question (')' or '}')
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// A `(` was matched with a `}` or vice-versa.
    MismatchedParens {
        /// The opening parenthesis ('(' or '{')
        open_ch: char,
        /// The position of the opening parethesis.
        open_pos: usize,
        /// The closing parenthesis (')' or '}')
        close_ch: char,
        /// The position of the closing parethesis.
        close_pos: usize,
    },
    /// A node had the wrong name.
    IncorrectName {
        /// The name that was found.
        actual: String,
        /// The name that was expected.
        expected: &'static str,
    },
    /// A node had the wrong number of children.
    IncorrectNumberOfChildren {
        /// A description of the node in question.
        description: &'static str,
        /// The number of children the node had.
        n_children: usize,
        /// The minimum of children the node should have had.
        minimum: Option<usize>,
        /// The minimum of children the node should have had.
        maximum: Option<usize>,
    },
    /// A Taproot child occurred somewhere it was not allowed.
    IllegalCurlyBrace {
        /// The position of the opening curly brace.
        pos: usize,
    },
    ///  Multiple separators (':' or '@') appeared in a node name.
    MultipleSeparators {
        /// The separator in question.
        separator: char,
        /// The position of the second separator.
        pos: usize,
    },
    /// Data occurred after the final ).
    TrailingCharacter {
        /// The first trailing character.
        ch: char,
        /// Its byte-index into the string.
        pos: usize,
    },
    /// A node's name was not recognized.
    UnknownName {
        /// The name that was not recognized.
        name: String,
    },
}

impl From<checksum::Error> for ParseTreeError {
    fn from(e: checksum::Error) -> Self { Self::Checksum(e) }
}

/// Error parsing a number.
#[derive(Clone, PartialEq, Eq)]
pub enum ParseNumError {
    /// Failed to parse the number at all.
    StdParse(num::ParseIntError),
    /// Number had a leading zero, + or -.
    InvalidLeadingDigit(char),
    /// Number was 0 in a context where zero is not allowed.
    ///
    /// Be aware that locktimes have their own error types and do not use this variant.
    IllegalZero {
        /// A description of the location where 0 was not allowed.
        context: &'static str,
    },
}

/// Error parsing a threshold expression.
#[derive(Clone, PartialEq, Eq)]
pub enum ParseThresholdError {
    /// Expression had no children, not even a threshold value.
    NoChildren,
    /// The threshold value appeared to be a sub-expression rather than a number.
    KNotTerminal,
    /// A 1-of-n threshold was used in a context it was not allowed.
    IllegalOr,
    /// A n-of-n threshold was used in a context it was not allowed.
    IllegalAnd,
    /// Failed to parse the threshold value.
    ParseK(ParseNumError),
    /// Threshold parameters were invalid.
    Threshold(ThresholdError),
}

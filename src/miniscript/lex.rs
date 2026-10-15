// SPDX-License-Identifier: CC0-1.0

//! Lexer
//!
//! Translates a script into a reversed sequence of tokens
//!


use crate::prelude::*;

/// Atom of a tokenized version of a script
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Token {
    BoolAnd,
    BoolOr,
    Add,
    Equal,
    NumEqual,
    CheckSig,
    CheckSigAdd,
    CheckMultiSig,
    CheckSequenceVerify,
    CheckLockTimeVerify,
    FromAltStack,
    ToAltStack,
    Drop,
    Dup,
    If,
    IfDup,
    NotIf,
    Else,
    EndIf,
    ZeroNotEqual,
    Size,
    Swap,
    Verify,
    Num(u32),
    Hash20([u8; 20]),
    Bytes32([u8; 32]),
    Bytes33([u8; 33]),
    Bytes65([u8; 65]),
}

#[derive(Clone)]
/// Iterator that goes through a vector of tokens backward (our parser wants to read
/// backward and this is more efficient anyway since we can use `Vec::pop()`).
pub struct TokenIter(Vec<Token>);

impl TokenIter {
    /// Create a new TokenIter
    pub fn new(v: Vec<Token>) -> TokenIter { TokenIter(v) }

    /// Look at the top at Iterator
    pub fn peek(&self) -> Option<&Token> { self.0.last() }

    /// Push a value to the iterator
    /// This will be first value consumed by popun_
    pub fn un_next(&mut self, tok: Token) { self.0.push(tok) }

    /// The len of the iterator
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns true if iterator is empty.
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

impl Iterator for TokenIter {
    type Item = Token;

    fn next(&mut self) -> Option<Token> { self.0.pop() }
}

/// Lexer error.
#[derive(Clone, PartialEq, Eq)]
pub enum Error {
    /// Parsed a negative number.
    InvalidInt {
        /// The bytes of the push that were attempted to be parsed.
        bytes: bitcoin::script::PushBytesBuf,
        /// The error that occurred.
        err: bitcoin::script::Error,
    },
    /// Parsed an opcode outside of the Miniscript language.
    InvalidOpcode(bitcoin::Opcode),
    /// Parsed a negative number.
    NegativeInt {
        /// The bytes of the push that were parsed to a negative number.
        bytes: bitcoin::script::PushBytesBuf,
        /// The resulting number.
        n: i64,
    },
    /// Non-minimal verify (e.g. `CHECKSIG VERIFY` in place of `CHECKSIGVERIFY`).
    NonMinimalVerify(Token),
    /// Error iterating through script.
    Script(bitcoin::script::Error),
}

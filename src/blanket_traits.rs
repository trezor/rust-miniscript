// SPDX-License-Identifier: CC0-1.0

//! Blanket Traits
//!
//! Because of this library's heavy use of generics, we often require complicated
//! trait bounds (especially when it comes to [`FromStr`] and its
//! associated error types). These blanket traits act as aliases, allowing easier
//! descriptions of them.
//!
//! While these traits are not sealed, they have blanket-impls which prevent you
//! from directly implementing them on your own types. The traits will be
//! automatically implemented if you satisfy all the bounds.
//!

use core::str::FromStr;

use crate::MiniscriptKey;

/// Auxiliary trait indicating that a type implements both `Display`, `Send` and `Sync`.
// NOTE: `Send` / `Sync` is required to maintain compatibility with downstream error handling libraries.
pub trait StaticDebugAndDisplay: Send + Sync + 'static {}

impl<T: Send + Sync + 'static> StaticDebugAndDisplay for T {}

/// Blanket trait describing a key where all associated types implement `FromStr`,
/// and all `FromStr` errors can be displayed.
pub trait FromStrKey:
    MiniscriptKey<
    > + FromStr<Err = Self::_FromStrErr>
{
    /// Dummy type. Do not use.
    type _FromStrErr: StaticDebugAndDisplay;
}

impl<T> FromStrKey for T
where
    Self: MiniscriptKey + FromStr,
    <Self as FromStr>::Err: StaticDebugAndDisplay,
{
    type _FromStrErr = <T as FromStr>::Err;
}

// SPDX-License-Identifier: CC0-1.0

use bitcoin::hashes::Hash;
use bitcoin::script;
use bitcoin::PubkeyHash;

use crate::miniscript::context;
use crate::{ScriptContext, ToPublicKey};

// trait for pushing key that depend on context
pub(crate) trait MsKeyBuilder {
    /// Serialize the key as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;

    /// Serialize the key hash as bytes based on script context. Used when encoding miniscript into bitcoin script
    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext;
}

impl MsKeyBuilder for script::Builder {
    fn push_ms_key<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_key(&key.to_public_key()),
            context::SigType::Schnorr => self.push_slice(key.to_x_only_pubkey().serialize()),
        }
    }

    fn push_ms_key_hash<Pk, Ctx>(self, key: &Pk) -> Self
    where
        Pk: ToPublicKey,
        Ctx: ScriptContext,
    {
        match Ctx::sig_type() {
            context::SigType::Ecdsa => self.push_slice(key.to_public_key().pubkey_hash()),
            context::SigType::Schnorr => {
                self.push_slice(PubkeyHash::hash(&key.to_x_only_pubkey().serialize()))
            }
        }
    }
}

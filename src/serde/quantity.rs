//! Serde functions for encoding primitive numbers using the Ethereum JSON-RPC "quantity" format.
//!
//! This is defined as a "hex encoded unsigned integer", with a special case of 0 being `0x0`.
//!
//! A regex for this format is: `^0x([1-9a-f]+[0-9a-f]*|0)$`.
//!
//! This is only valid for human-readable [`serde`] implementations.
//! For non-human-readable implementations, the format is unspecified.
//! Currently, it uses a fixed-width big-endian byte-array.

use private::ConvertRuint;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Serializes a primitive number as a "quantity" hex string.
pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: ConvertRuint,
    S: Serializer,
{
    value.into_ruint().serialize(serializer)
}

/// Deserializes a primitive number from a "quantity" hex string.
pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: ConvertRuint,
    D: Deserializer<'de>,
{
    T::Ruint::deserialize(deserializer).map(T::from_ruint)
}

/// Private implementation details of the [`quantity`](self) module.
#[allow(unnameable_types)]
mod private {
    #[doc(hidden)]
    pub trait ConvertRuint: Copy + Sized {
        // We have to use `Try*` traits because `From` is not implemented by ruint types.
        // They shouldn't ever error.
        type Ruint: Copy
            + serde::Serialize
            + serde::de::DeserializeOwned
            + TryFrom<Self>
            + TryInto<Self>;

        #[inline]
        fn into_ruint(self) -> Self::Ruint {
            self.try_into().ok().unwrap()
        }

        #[inline]
        fn from_ruint(ruint: Self::Ruint) -> Self {
            ruint.try_into().ok().unwrap()
        }
    }

    macro_rules! impl_from_ruint {
        ($($primitive:ty = $ruint:ty),* $(,)?) => {
            $(
                impl ConvertRuint for $primitive {
                    type Ruint = $ruint;
                }
            )*
        };
    }

    impl_from_ruint! {
        bool = alloy_primitives::ruint::aliases::U1,
        u8   = alloy_primitives::U8,
        u16  = alloy_primitives::U16,
        u32  = alloy_primitives::U32,
        u64  = alloy_primitives::U64,
        u128 = alloy_primitives::U128,
    }
}

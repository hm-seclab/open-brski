#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use openssl::*;

#[cfg(all(not(feature = "openssl")))]
mod nossl;
#[cfg(all(not(feature = "openssl")))]
pub use nossl::*;

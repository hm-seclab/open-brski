#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use openssl::*;

#[cfg(not(feature = "openssl"))]
mod nossl;
#[cfg(not(feature = "openssl"))]
pub use nossl::*;

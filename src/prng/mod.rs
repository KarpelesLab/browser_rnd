//! Raw pseudo-random number generators, independent of any browser's
//! output-conversion quirks.

pub mod lcg;
pub mod xorshift128plus;

pub use lcg::Lcg;
pub use xorshift128plus::XorShift128Plus;

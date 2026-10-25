//! Core library for reading Nintendo Switch content containers (NSP/NSZ/XCI/XCZ)
//! and repacking them into multi-content XCI files.

pub mod bktr;
pub mod build;
pub mod cnmt;
pub mod compressed;
pub mod container;
pub mod crypto;
pub mod error;
pub mod extract;
pub mod keys;
pub mod nacp;
pub mod nca;
pub mod ncz;
pub mod plan;
pub mod regions;
pub mod romfs;
pub mod rsv;
pub mod scan;
pub mod storage;
pub mod ticket;
pub mod titledb;
pub mod util;

#[cfg(test)]
pub(crate) mod testutil;

pub use error::{Error, Result};
pub use keys::Keys;

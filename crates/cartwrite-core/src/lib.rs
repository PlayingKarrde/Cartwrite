//! Core library for reading Nintendo Switch content containers (NSP/NSZ/XCI/XCZ)
//! and repacking them into multi-content XCI files.

pub mod build;
pub mod cnmt;
pub mod container;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod nacp;
pub mod nca;
pub mod ncz;
pub mod plan;
pub mod romfs;
pub mod rsv;
pub mod scan;
pub mod ticket;
pub mod titledb;
pub mod util;

pub use error::{Error, Result};
pub use keys::Keys;

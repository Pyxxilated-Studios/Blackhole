#![allow(incomplete_features)]
#![forbid(unsafe_code)]
#![feature(
    array_try_from_fn,
    async_fn_in_trait,
    ip,
    once_cell,
    option_get_or_insert_default
)]

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
pub mod schedule;
pub mod server;
pub mod statistics;

#![feature(
    array_try_from_fn,
    associated_type_defaults,
    async_closure,
    min_specialization,
    once_cell
)]

pub mod api;
pub mod cache;
pub mod config;
pub mod dns;
pub mod filter;
pub mod server;
pub mod statistics;

//! Per-screen UI drawing, split out of `main.rs` by the tab/screen it renders.
//! Each file adds `impl crate::App` methods for one area; `main.rs` keeps the
//! `App` struct, its init, the frame loop and command dispatch.

mod dashboard;
mod history;
mod history_table;
mod proxy;

pub(crate) use history::HistFilter;
pub(crate) use history_table::history_table;

pub mod editor;
pub mod theme;
#[cfg(target_os = "macos")]
pub mod macmenu;

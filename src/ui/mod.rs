//! Per-screen UI drawing, split out of `main.rs` by the tab/screen it renders.
//! Each file adds `impl crate::App` methods for one area; `main.rs` keeps the
//! `App` struct, its init, the frame loop and command dispatch.

mod dashboard;

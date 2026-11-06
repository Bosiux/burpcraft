//! Extensions (Pro-style): out-of-process plugins in any language, a BApp Store served by a
//! self-hosted `burpcraft-server`, and the BChecks editor.
//!
//! Extension protocol: the extension is an executable started with piped stdin/stdout; every
//! message is one JSON object per line. BurpCraft sends:
//!   {"type":"hello","api":"burpcraft-ext/1"}
//!   {"type":"request","id":7,"host":"a.test","port":443,"tls":true,"request":"<base64>"}
//!       (only if the extension registered the "request" hook; reply within 2 s with
//!        {"type":"request","id":7,"request":"<base64>"} to replace it, or {"type":"continue","id":7})
//!   {"type":"response","url":"https://a.test/x","request":"<base64>","response":"<base64>"}
//! The extension may send at any time:
//!   {"type":"register","name":"My extension","hooks":["request","response"]}
//!   {"type":"issue","name":"...","severity":"high|medium|low|info","url":"https://...","detail":"..."}
//!   {"type":"log","message":"..."}

mod runtime;
mod store;
mod ui;

pub use runtime::{init, on_request, on_response};
pub use ui::Tab;

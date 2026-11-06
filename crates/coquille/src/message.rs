//! Messages, as JSON values: those received (from the terminal, a child, or
//! routed internally to `["$shell"]`), and those emitted. The protocol is
//! buche's driver protocol (see ~/bu/buche: src/driver-exchange); most
//! messages are relayed as they are, so they are kept as JSON throughout.

use serde_json::{Value, json};

pub type Message = Value;

/// The shell's own address.
pub const SELF: [&str; 2] = ["$proc", "cq"];

/// A feature of the shell language that coquille doesn't run (yet).
#[derive(Debug)]
pub struct NotImplemented(pub String);

impl std::fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Feature not implemented: {}", self.0)
    }
}

impl std::error::Error for NotImplemented {}

pub fn not_implemented(feature: impl Into<String>) -> anyhow::Error {
    NotImplemented(feature.into()).into()
}

/// The kind of an error, as the terminal is told it (`error_type`).
fn error_type(err: &anyhow::Error) -> String {
    if err.downcast_ref::<NotImplemented>().is_some() {
        return "FeatureNotImplemented".into();
    }
    if let Some(code) = err.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error()) {
        return format!("{:?}", nix::errno::Errno::from_raw(code));
    }
    "Error".into()
}

/// Build an `error` message from an error.
pub fn make_error(err: &anyhow::Error) -> Message {
    json!({
        "type": "error",
        "to": ["$term"],
        "from": SELF,
        "error_type": error_type(err),
        "message": err.to_string(),
        "traceback": err.chain().skip(1).map(|e| e.to_string()).collect::<Vec<_>>(),
    })
}

/// A message's `type`.
pub fn kind(msg: &Message) -> &str {
    msg.get("type").and_then(Value::as_str).unwrap_or("")
}

/// The first segment of a message's `to`.
pub fn to_head(msg: &Message) -> Option<&str> {
    msg.get("to")?.as_array()?.first()?.as_str()
}

/// The length of a message's `from` (what it says of where it comes from).
pub fn from_len(msg: &Message) -> Option<usize> {
    Some(msg.get("from")?.as_array()?.len())
}

/// The segment `i` of a message's `from`.
pub fn from_at(msg: &Message, i: usize) -> Option<&str> {
    msg.get("from")?.as_array()?.get(i)?.as_str()
}

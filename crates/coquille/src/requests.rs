//! Pending approval requests: things the shell wants the user's go-ahead
//! for (reloading a configuration that changed, trusting a directory's). The
//! prompt's context says when some are pending; the `requests` builtin opens
//! a view of them, where the user approves or ignores each one.

use serde_json::{Value, json};

/// A pending request, as the requests view shows it.
#[derive(Clone, Debug)]
pub struct PendingRequest {
    /// Identifies the request (answers name it).
    pub id: String,
    /// What is asked, in a few words: in the prompt's context, when it is
    /// the only one pending.
    pub summary: String,
    /// What is asked, as the view's heading.
    pub title: String,
    /// Details, one line each (e.g. the files that changed).
    pub details: Vec<String>,
    /// The labels of the approve and ignore buttons.
    pub approve: String,
    pub ignore: String,
}

impl PendingRequest {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "summary": self.summary,
            "title": self.title,
            "details": self.details,
            "approve": self.approve,
            "ignore": self.ignore,
        })
    }
}

/// The user's answer to a request, from the view.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer {
    Approve,
    Ignore,
}

/// What the prompt's context says about the pending requests (None: none).
pub fn pending_summary(requests: &[PendingRequest]) -> Option<String> {
    match requests {
        [] => None,
        [one] => Some(one.summary.clone()),
        many => Some(format!("{} requests are pending", many.len())),
    }
}

/// The requests view's page. It shows the requests it is given with
/// `cqRender(requests)` (see render_requests), and answers with `{request,
/// answer}` (approve or ignore) or `{dismiss: true}` (Escape). Keyboard: ↑/↓
/// (or k/j) select, Enter or a approves, i or Delete ignores, Escape closes.
pub const REQUESTS_HTML: &str = include_str!("../resources/requests.html");

/// The view command that shows `requests` (an `exec`: our own code, the
/// requests as JSON data in it).
pub fn render_requests(requests: &[PendingRequest]) -> Value {
    let data = Value::Array(requests.iter().map(PendingRequest::to_json).collect());
    json!({ "type": "exec", "code": format!("window.cqRender({data})") })
}

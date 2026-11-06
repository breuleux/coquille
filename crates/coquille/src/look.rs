//! How a command's cells look (see buche's CellConfiguration `label`, `icon`).
//! The program's own cells (its GUI, say) show its initial in cursive, in the
//! command's colour, and a sans-serif label; its terminal (`$stdout`, and the
//! placeholder standing in for it until its output comes) a console icon and
//! a monospace label.

use serde_json::{Map, Value, json};

use crate::message::{Message, kind};

const CONSOLE_SVG: &str = concat!(
    r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="none" stroke="#000" "##,
    r#"stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">"#,
    r#"<rect x="1" y="2" width="14" height="12" rx="2"/><path d="M4 6l2.5 2L4 10M8 10.5h4"/></svg>"#,
);

/// The coquille logo: this shell's prompt icon. It keeps its colours (unlike
/// the masked console icon, which follows the text colour).
pub fn logo() -> Value {
    json!({ "type": "image", "mimetype": "image/svg+xml", "data": include_str!("../resources/cq.svg") })
}

/// The icon of a program's terminal: only its shape counts, painted in the
/// tab's text colour.
fn console_icon() -> Value {
    json!({ "type": "image", "mimetype": "image/svg+xml", "mask": true, "data": CONSOLE_SVG })
}

/// `text`, all in one style (an accent: "mono", "sans"...).
pub fn styled_all(text: &str, style: &str) -> Value {
    json!({ "parts": [{ "text": text, "style": style }] })
}

/// A program's icon: its initial, in cursive and `color`.
pub fn program_icon(program: &str, color: Option<&str>) -> Value {
    let base = program.rsplit('/').next().unwrap_or(program);
    let initial = base.chars().find(|c| c.is_alphanumeric()).map_or("?".into(), |c| c.to_uppercase().to_string());
    let mut icon = json!({ "type": "glyph", "text": initial, "font": "cursive" });
    if let Some(color) = color.filter(|c| !c.is_empty()) {
        icon["color"] = json!(color);
    }
    icon
}

/// The look of a program's cells: its icon, and a sans-serif label.
pub fn program_look(verb: &str, color: Option<&str>) -> Map<String, Value> {
    let mut look = Map::new();
    look.insert("label".into(), styled_all(verb, "sans"));
    look.insert("icon".into(), program_icon(verb, color));
    look
}

/// The text of structured text's parts (groups' included).
pub fn parts_text(parts: &[Value]) -> String {
    parts
        .iter()
        .map(|p| {
            if let Some(text) = p.get("text").and_then(Value::as_str) {
                text.to_owned()
            } else if let Some(group) = p.get("group").and_then(Value::as_array) {
                parts_text(group)
            } else {
                String::new()
            }
        })
        .collect()
}

/// What a program run from here says about what it shows (its prompts, its
/// own cells): when it names it (a `label`) but chooses no icon, the look of
/// a program's cells, with `program`'s icon. A program that chose an icon
/// (another shell, say) keeps its own look.
pub fn with_program_look(mut event: Message, program: &str, color: Option<&str>) -> Message {
    if kind(&event) != "configure" {
        return event;
    }
    let Some(obj) = event.as_object_mut() else { return event };
    if obj.contains_key("icon") {
        return event;
    }
    let Some(label) = obj.get("label") else { return event };
    if let Some(text) = label.as_str() {
        obj.insert("label".into(), styled_all(text, "sans"));
    }
    obj.insert("icon".into(), program_icon(program, color));
    event
}

/// After configuring a process with `decoration`: the message giving its
/// placeholder the terminal's look (a console icon and a monospace label),
/// and that look, for its `$stdout` to be declared with once its output
/// comes (see Process::stdout_look). Nothing without a decoration.
pub fn terminal_decorations(process_addr: &[String], decoration: Option<&Map<String, Value>>) -> (Option<Message>, Value) {
    let Some(label) = decoration.and_then(|d| d.get("label")) else {
        return (None, json!({}));
    };
    let verb = match label {
        Value::String(s) => s.clone(),
        other => parts_text(other.get("parts").and_then(Value::as_array).map_or(&[], |v| v)),
    };
    let look = json!({ "label": styled_all(&verb, "mono"), "icon": console_icon() });
    let mut from = process_addr.to_vec();
    from.push("?".into());
    let message = crate::util::merged(json!({ "type": "configure", "from": from, "to": ["$term"] }), look.clone());
    (Some(message), look)
}

/// Command verb for the echo label: the command word of the LAST simple
/// command of the line — pipes and sequences ("ls | grep x", "cd x; ls")
/// keep the last one, and the first bare word of that segment is taken
/// (skipping punctuation like subshell parens, and leading environment
/// assignments).
pub fn command_verb(text: &str) -> String {
    let last = text
        .split([';', '|', '&', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .next_back()
        .unwrap_or("");
    let is_assignment = |w: &&str| {
        w.split_once('=')
            .is_some_and(|(name, _)| !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_'))
    };
    last.split(|c: char| c.is_whitespace() || c == '(' || c == ')')
        .filter(|w| !w.is_empty())
        .find(|w| !is_assignment(w))
        .unwrap_or("")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbs() {
        assert_eq!(command_verb("ls | grep x"), "grep");
        assert_eq!(command_verb("cd x; FOO=1 git status"), "git");
        assert_eq!(command_verb("(make)"), "make");
        assert_eq!(command_verb(""), "");
    }

    #[test]
    fn icons() {
        assert_eq!(program_icon("/usr/bin/ls", Some("red")), json!({"type": "glyph", "text": "L", "font": "cursive", "color": "red"}));
        assert_eq!(program_icon("./-", None)["text"], "?");
    }
}

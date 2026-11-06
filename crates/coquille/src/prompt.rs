//! The prompt's text, from its configuration (see config::PromptSpec), and
//! the contexts derived from it (an echo's, the prompt's own).

use std::collections::HashMap;
use std::sync::LazyLock;

use md5::{Digest, Md5};
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::config::{PartSpec, PromptSpec};
use crate::util::{put_opt, tildify};

/// A path, shortened: `~` for home, and only its last two directories.
fn short_path(file: &str) -> String {
    let short = tildify(file);
    let in_home = short == "~" || short.starts_with("~/");
    let rest = if in_home { &short[1..] } else { &short[..] };
    let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 2 { short } else { format!("... {}", parts[parts.len() - 2..].join("/")) }
}

/// An accent picked from `text`: a hue (H0 to H359).
fn hue(text: &str) -> String {
    let digest = Md5::digest(text.as_bytes());
    format!("H{}", u128::from_be_bytes(digest.into()) % 360)
}

/// What can follow a variable in a template, as `${NAME|filter|...}`: each
/// makes a value of the one before (an empty one stays empty, to hide what it
/// is in, as the variable would).
const FILTERS: &[(&str, fn(&str) -> String)] = &[
    // An accent picked from the value (H0 to H359): e.g. a host's own.
    ("hue", hue),
    // A path with the home directory as ~.
    ("tilde", tildify),
    // A path, shortened: ~ for home, and its last two directories.
    ("short", short_path),
];

fn filter(name: &str) -> Option<fn(&str) -> String> {
    FILTERS.iter().find(|(n, _)| *n == name).map(|(_, f)| *f)
}

/// `${NAME}` or `${NAME|filter|...}` (spaces allowed around the bars).
static BRACED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*((?:\|\s*[A-Za-z_][A-Za-z0-9_]*\s*)*)\}").unwrap()
});
static BARE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*").unwrap());

fn filters_of(spec: &str) -> Vec<&str> {
    spec.split('|').skip(1).map(str::trim).collect()
}

/// What is wrong with a template, if anything (see expand_template).
pub fn template_problem(template: &str) -> Option<String> {
    let mut i = 0;
    while let Some(pos) = template[i..].find('$') {
        let rest = &template[i + pos + 1..];
        i += pos + 1;
        if rest.starts_with('$') {
            i += 1;
        } else if rest.starts_with('(') {
            return Some(
                "commands ($(…)) are not run in templates: have a daemon set a variable instead"
                    .into(),
            );
        } else if rest.starts_with('{') {
            let Some(m) = BRACED.captures(rest) else {
                return Some(format!("malformed ${{…}} in {template:?}"));
            };
            for f in filters_of(&m[2]) {
                if filter(f).is_none() {
                    let known: Vec<_> = FILTERS.iter().map(|(n, _)| *n).collect();
                    return Some(format!(
                        "unknown filter {f:?} (expected one of: {})",
                        known.join(", ")
                    ));
                }
            }
        }
    }
    None
}

/// The result of expanding a template: its text, and whether any of its
/// substitutions came out empty (which hides the group it is in).
pub struct Expansion {
    pub text: String,
    pub blank: bool,
}

/// Expand a template: `$NAME` and `${NAME}` by `vars`, `${NAME|filter|...}`
/// the same, then through the filters (see FILTERS), `$$` by a dollar sign.
/// Anything else (a malformed `${`, an unknown filter: see template_problem)
/// is taken literally.
pub fn expand_template(template: &str, vars: &dyn Fn(&str) -> Option<String>) -> Expansion {
    let mut text = String::new();
    let mut blank = false;
    let mut i = 0;
    while i < template.len() {
        let Some(pos) = template[i..].find('$') else {
            text.push_str(&template[i..]);
            break;
        };
        text.push_str(&template[i..i + pos]);
        i += pos;
        let rest = &template[i + 1..];
        if rest.starts_with('$') {
            text.push('$');
            i += 2;
            continue;
        }
        let (name, filters, len) = if let Some(m) = BRACED.captures(rest) {
            (m.get(1).unwrap().as_str(), filters_of(m.get(2).unwrap().as_str()), m[0].len())
        } else if let Some(m) = BARE.find(rest) {
            (m.as_str(), vec![], m.len())
        } else {
            text.push('$');
            i += 1;
            continue;
        };
        let Some(filters) = filters.iter().map(|f| filter(f)).collect::<Option<Vec<_>>>() else {
            text.push('$');
            i += 1;
            continue;
        };
        let mut value = vars(name).unwrap_or_default();
        for f in filters {
            if !value.is_empty() {
                value = f(&value);
            }
        }
        blank |= value.is_empty();
        text.push_str(&value);
        i += 1 + len;
    }
    Expansion { text, blank }
}

/// The prompt's text and accent (the echoes' colour).
pub struct PromptLook {
    pub parts: Vec<Value>,
    pub color: String,
}

/// The host's name, short.
pub fn hostname() -> String {
    let name = nix::unistd::gethostname().map(|h| h.to_string_lossy().into_owned());
    name.unwrap_or_default().split('.').next().unwrap_or_default().to_owned()
}

/// Render the prompt text from its configuration. Its own variables are
/// HOSTNAME (the host's name, short) and PWD (the working directory); then
/// its `vars`, in order (each can use those before it), of which COLOR is
/// its accent; then `lookup` (the shell's variables and the environment). It
/// runs nothing: rendering it again whenever a variable changes is cheap.
pub fn render_prompt(
    spec: &PromptSpec,
    cwd: &str,
    lookup: &dyn Fn(&str) -> Option<String>,
) -> PromptLook {
    let mut own: HashMap<String, String> = HashMap::new();
    own.insert("HOSTNAME".into(), hostname());
    own.insert("PWD".into(), cwd.into());
    for (name, template) in &spec.vars {
        let value = {
            let vars = |n: &str| own.get(n).cloned().or_else(|| lookup(n));
            expand_template(template, &vars).text
        };
        own.insert(name.clone(), value);
    }
    let vars = |n: &str| own.get(n).cloned().or_else(|| lookup(n));
    let color = own.get("COLOR").cloned().unwrap_or_default();
    let (parts, _) = render_parts(&spec.parts, &vars);
    PromptLook { parts, color }
}

/// An action, its variables expanded (in a command line).
fn expand_action(action: &Value, vars: &dyn Fn(&str) -> Option<String>) -> Value {
    match action {
        Value::String(s) => json!(expand_template(s, vars).text),
        Value::Object(o) if o.contains_key("command") => {
            let mut o = o.clone();
            let command = o["command"].as_str().unwrap_or_default();
            o["command"] = json!(expand_template(command, vars).text);
            Value::Object(o)
        }
        other => other.clone(),
    }
}

/// Render parts: the parts, and whether any substitution came out empty.
fn render_parts(specs: &[PartSpec], vars: &dyn Fn(&str) -> Option<String>) -> (Vec<Value>, bool) {
    let mut parts = Vec::new();
    let mut blank = false;
    let style_of = |style: &Option<String>| {
        style.as_ref().map(|s| expand_template(s, vars).text).filter(|s| !s.is_empty())
    };
    for spec in specs {
        let mut part = Map::new();
        match spec {
            PartSpec::Group { group, style, action } => {
                // Hidden if a substitution in it came out empty (which then
                // stops there: the parts around it stay).
                let (inner, inner_blank) = render_parts(group, vars);
                if inner_blank || inner.is_empty() {
                    continue;
                }
                let style = style_of(style);
                // A plain group (no style, no action) needs no group in buche.
                if style.is_none() && action.is_none() {
                    parts.extend(inner);
                    continue;
                }
                part.insert("group".into(), Value::Array(inner));
                put_opt(&mut part, "style", style);
                put_opt(&mut part, "action", action.as_ref().map(|a| expand_action(a, vars)));
            }
            PartSpec::Spacer { action } => {
                part.insert("spacer".into(), json!("grow"));
                put_opt(&mut part, "action", action.as_ref().map(|a| expand_action(a, vars)));
            }
            PartSpec::Text { text, style, action } => {
                let text = expand_template(text, vars);
                blank |= text.blank;
                if text.text.is_empty() {
                    continue;
                }
                part.insert("text".into(), json!(text.text));
                put_opt(&mut part, "style", style_of(style));
                put_opt(&mut part, "action", action.as_ref().map(|a| expand_action(a, vars)));
            }
        }
        parts.push(Value::Object(part));
    }
    (parts, blank)
}

/// The context of an echo of a command submitted now with the prompt
/// looking like `parts`: the prompt text, then the time, right-aligned.
pub fn prompt_context(parts: &[Value]) -> Value {
    let clock = chrono::Local::now().format("%H:%M:%S").to_string();
    let mut parts = parts.to_vec();
    parts.push(json!({ "spacer": "grow" }));
    parts.push(json!({ "text": clock, "style": "grey L60" }));
    json!({ "parts": parts })
}

/// The prompt's own context: the prompt text, then, given `pending` (what is
/// pending: see requests::pending_summary), a right-aligned notice of it in
/// orange, which opens the requests view when clicked.
pub fn prompt_marker(parts: &[Value], pending: Option<String>) -> Value {
    let mut parts = parts.to_vec();
    if let Some(pending) = pending {
        parts.push(json!({ "spacer": "grow" }));
        parts.push(json!({ "text": pending, "style": "orange", "action": { "builtin": "requests" } }));
    }
    json!({ "parts": parts })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(name: &str) -> Option<String> {
        match name {
            "A" => Some("alpha".into()),
            "P" => Some("/x/y/z/w".into()),
            _ => None,
        }
    }

    #[test]
    fn expands_templates() {
        let e = expand_template("$A-${A}-$$-${ P | short }-$NOPE", &vars);
        assert_eq!(e.text, "alpha-alpha-$-... z/w-");
        assert!(e.blank);
        let e = expand_template("${A|hue}", &vars);
        assert!(e.text.starts_with('H') && !e.blank);
        assert_eq!(expand_template("$ {A}", &vars).text, "$ {A}");
    }

    #[test]
    fn template_problems() {
        assert!(template_problem("$(ls)").is_some());
        assert!(template_problem("${A|nope}").is_some());
        assert!(template_problem("${A").is_some());
        assert!(template_problem("$$(ls) ${A|tilde}").is_none());
    }

    #[test]
    fn groups_hide_when_blank() {
        let spec = PromptSpec {
            vars: vec![("COLOR".into(), "red".into())],
            parts: vec![
                PartSpec::Text { text: "$A".into(), style: Some("$COLOR".into()), action: None },
                PartSpec::Group {
                    group: vec![
                        PartSpec::Text { text: " - ".into(), style: None, action: None },
                        PartSpec::Text { text: "$NOPE".into(), style: None, action: None },
                    ],
                    style: None,
                    action: None,
                },
            ],
        };
        let look = render_prompt(&spec, "/", &vars);
        assert_eq!(look.color, "red");
        assert_eq!(look.parts, vec![json!({"text": "alpha", "style": "red"})]);
    }
}

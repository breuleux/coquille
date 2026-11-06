//! The builtins: commands the shell runs itself. Each says what it asks the
//! shell to do (see Shell::run_builtin); control commands ask the same with
//! messages to ["$shell"] (see Shell::handle).

pub const BUILTIN_NAMES: &[&str] = &["cd", "set", "export", "nuke", "daemon"];

pub fn is_builtin(name: &str) -> bool {
    BUILTIN_NAMES.contains(&name)
}

/// What a builtin asks the shell to do.
#[derive(Clone, Debug, PartialEq)]
pub enum BuiltinEvent {
    Cd { path: String },
    Set { name: String, value: String, export: bool },
    Nuke,
    DaemonSet { name: String, cmd: String, args: Vec<String>, restart_ms: Option<u64> },
    DaemonEnable { name: String },
    DaemonDisable { name: String },
}

fn assignments(args: &[String], export: bool) -> Vec<BuiltinEvent> {
    args.iter()
        .filter_map(|arg| arg.split_once('='))
        .map(|(name, value)| BuiltinEvent::Set { name: name.into(), value: value.into(), export })
        .collect()
}

/// What builtin `name` asks for, given `args`. Errors are usage errors.
pub fn builtin_events(name: &str, args: &[String]) -> anyhow::Result<Vec<BuiltinEvent>> {
    Ok(match name {
        "cd" => {
            let path = args.first().cloned().unwrap_or_else(|| crate::util::home().to_string_lossy().into_owned());
            vec![BuiltinEvent::Cd { path }]
        }
        "set" => assignments(args, false),
        "export" => assignments(args, true),
        "nuke" => vec![BuiltinEvent::Nuke],
        "daemon" => {
            let usage = || anyhow::anyhow!("usage: daemon set NAME [-tMS] COMMAND... | daemon enable NAME | daemon disable NAME");
            let (sub, name, rest) = match args {
                [sub, name, rest @ ..] => (sub.as_str(), name.clone(), rest),
                _ => return Err(usage()),
            };
            match sub {
                "set" => {
                    let (restart_ms, rest) = match rest.first().and_then(|a| a.strip_prefix("-t")) {
                        Some(ms) => (Some(ms.parse().map_err(|_| anyhow::anyhow!("daemon set: bad delay {ms:?}"))?), &rest[1..]),
                        None => (None, rest),
                    };
                    let [cmd, args @ ..] = rest else { return Err(usage()) };
                    vec![BuiltinEvent::DaemonSet { name, cmd: cmd.clone(), args: args.to_vec(), restart_ms }]
                }
                "enable" => vec![BuiltinEvent::DaemonEnable { name }],
                "disable" => vec![BuiltinEvent::DaemonDisable { name }],
                _ => return Err(usage()),
            }
        }
        _ => anyhow::bail!("not a builtin: {name}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(args: &[&str]) -> Vec<String> {
        args.iter().map(|a| a.to_string()).collect()
    }

    #[test]
    fn parses() {
        assert_eq!(
            builtin_events("export", &s(&["A=1", "B", "C=x=y"])).unwrap(),
            vec![
                BuiltinEvent::Set { name: "A".into(), value: "1".into(), export: true },
                BuiltinEvent::Set { name: "C".into(), value: "x=y".into(), export: true },
            ]
        );
        assert_eq!(
            builtin_events("daemon", &s(&["set", "v", "-t500", "watch", "-x"])).unwrap(),
            vec![BuiltinEvent::DaemonSet { name: "v".into(), cmd: "watch".into(), args: s(&["-x"]), restart_ms: Some(500) }]
        );
        assert!(builtin_events("daemon", &s(&["set", "v"])).is_err());
    }
}

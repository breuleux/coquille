//! Word expansion: what a parsed word stands for, as arguments. The words
//! come from brush-parser as written (quotes and all); their pieces (quoted
//! text, `$NAME`, `$(…)`, `~`...) are expanded here, as the commands go: a
//! command's substitutions run when that command's words are expanded, as
//! bash does — in `cd /tmp; echo $(pwd)`, `pwd` sees the new directory.
//!
//! What coquille does (a subset of bash):
//!  - quotes, escapes, `$'…'`, tildes (`~`, `~user`, `~+`, `~-`);
//!  - parameters: `$NAME`, `${NAME}`, `${NAME:-default}`, `${NAME:+alt}`,
//!    `${NAME:?message}`, `${#NAME}` (shell variables, then the
//!    environment). Their values are not word-split (unlike bash's), but an
//!    unquoted empty one vanishes, as in bash;
//!  - command substitution, `$(…)` and `` `…` ``: unquoted, its output is
//!    split on IFS whitespace (and vanishes when empty); quoted, it is one
//!    word;
//!  - globbing (`*`, `?`, `[…]`, `**`), of the unquoted parts of words only,
//!    a pattern matching nothing standing for itself.
//!
//! Anything else (arithmetic, arrays, positional parameters...) is reported
//! as not implemented.

use std::rc::Rc;
use std::sync::LazyLock;

use anyhow::{Result, bail};
use brush_parser::ast;
use brush_parser::word::{Parameter, ParameterExpr, ParameterTestType, TildeExpr, WordPiece, WordPieceWithSource};
use regex::Regex;

use crate::message::not_implemented;
use crate::process::{OpenMode, Redirect};
use crate::shell::Shell;
use crate::util::{home, user_home};

static ENV_VAR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([^}]+)\}|\$([A-Za-z_][A-Za-z0-9_]*)").unwrap());

/// Expand `$NAME` and `${NAME}` in `text` by `lookup` (unset: empty).
pub fn expand_env_vars(text: &str, lookup: &dyn Fn(&str) -> Option<String>) -> String {
    ENV_VAR
        .replace_all(text, |c: &regex::Captures| {
            let name = c.get(1).or_else(|| c.get(2)).unwrap().as_str();
            lookup(name).unwrap_or_default()
        })
        .into_owned()
}

fn parse_word(word: &str) -> Result<Vec<WordPieceWithSource>> {
    brush_parser::word::parse(word, &Default::default()).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Parse a command line.
pub fn parse_program(text: &str) -> Result<ast::Program> {
    brush_parser::Parser::new(std::io::Cursor::new(text), &Default::default())
        .parse_program()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// A word with its quotes removed, but its expansions (`$NAME`, `$(…)`...)
/// left as written; a leading `~` is the home directory.
pub fn unquote_keeping_expansions(word: &str) -> std::result::Result<String, String> {
    fn go(word: &str, pieces: &[WordPieceWithSource], quoted: bool, out: &mut String) {
        for piece in pieces {
            match &piece.piece {
                WordPiece::Text(s) | WordPiece::SingleQuotedText(s) => out.push_str(s),
                WordPiece::AnsiCQuotedText(s) => out.push_str(&ansi_c_unescape(s)),
                WordPiece::EscapeSequence(s) => out.push_str(&unescape(s, quoted)),
                WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    go(word, inner, true, out)
                }
                WordPiece::TildeExpansion(TildeExpr::Home) => out.push_str(&home().to_string_lossy()),
                _ => out.push_str(word.get(piece.start_index..piece.end_index).unwrap_or_default()),
            }
        }
    }
    let pieces = parse_word(word).map_err(|e| e.to_string())?;
    let mut out = String::new();
    go(word, &pieces, false, &mut out);
    Ok(out)
}

/// An escape sequence (`\x`) as what it stands for: the character, outside
/// double quotes; within them, only for the characters it escapes there.
fn unescape(seq: &str, quoted: bool) -> String {
    let escaped = seq.strip_prefix('\\').unwrap_or(seq);
    match escaped {
        "\n" => String::new(),
        _ if !quoted || matches!(escaped, "$" | "`" | "\"" | "\\") => escaped.to_owned(),
        _ => seq.to_owned(),
    }
}

/// The text of a `$'…'` quote, its escapes resolved.
fn ansi_c_unescape(text: &str) -> String {
    let mut out = String::new();
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = chars.next() else {
            out.push('\\');
            break;
        };
        let digits = |chars: &mut std::iter::Peekable<std::str::Chars>, radix: u32, max: usize| {
            let mut s = String::new();
            while s.len() < max && chars.peek().is_some_and(|c| c.is_digit(radix)) {
                s.push(chars.next().unwrap());
            }
            u32::from_str_radix(&s, radix).ok().and_then(char::from_u32)
        };
        match e {
            'n' => out.push('\n'),
            't' => out.push('\t'),
            'r' => out.push('\r'),
            'a' => out.push('\x07'),
            'b' => out.push('\x08'),
            'e' | 'E' => out.push('\x1b'),
            'f' => out.push('\x0c'),
            'v' => out.push('\x0b'),
            'x' => out.extend(digits(&mut chars, 16, 2)),
            'u' => out.extend(digits(&mut chars, 16, 4)),
            'U' => out.extend(digits(&mut chars, 16, 8)),
            '0'..='7' => {
                let mut s = e.to_string();
                while s.len() < 3 && chars.peek().is_some_and(|c| c.is_digit(8)) {
                    s.push(chars.next().unwrap());
                }
                out.extend(u32::from_str_radix(&s, 8).ok().and_then(char::from_u32));
            }
            '\\' | '\'' | '"' | '?' => out.push(e),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    out
}

/// Word splitting of a substitution's result, as bash does it: whitespace
/// in IFS (space, tab and newline by default) delimits fields, runs of it
/// make one delimiter, and no field is empty. (Non-whitespace IFS
/// characters, which by the book also split, are taken literally; with such
/// an IFS alone, nothing splits.) Also: whether the result starts and ends
/// with a delimiter (which ends the field before, or after).
fn split_on_ifs(result: &str, ifs: Option<&str>) -> (Vec<String>, bool, bool) {
    let spaces: Vec<char> = match ifs {
        None => vec![' ', '\t', '\n'],
        Some(ifs) => ifs.chars().filter(|c| c.is_whitespace()).collect(),
    };
    if spaces.is_empty() {
        return (vec![result.to_owned()], false, false);
    }
    let fields = result.split(spaces.as_slice()).filter(|f| !f.is_empty()).map(str::to_owned).collect();
    (fields, result.starts_with(spaces.as_slice()), result.ends_with(spaces.as_slice()))
}

/// A piece of a word being expanded, and whether it may be globbed (it is
/// unquoted).
type Segment = (String, bool);

/// The words a word expands into, as they are made.
#[derive(Default)]
struct Fields {
    done: Vec<Vec<Segment>>,
    /// The word being made; None until something (even an empty quote)
    /// starts it — which is how an empty unquoted expansion vanishes.
    current: Option<Vec<Segment>>,
}

impl Fields {
    fn push(&mut self, text: String, globbable: bool) {
        self.current.get_or_insert_default().push((text, globbable));
    }

    fn end(&mut self) {
        if let Some(field) = self.current.take() {
            self.done.push(field);
        }
    }

    /// The result of an expansion: as is, in quotes; else split on IFS if
    /// `split`, and gone when empty.
    fn expansion(&mut self, text: String, quoted: bool, split: Option<Option<&str>>) {
        if quoted {
            return self.push(text, false);
        }
        let Some(ifs) = split else {
            if !text.is_empty() {
                self.push(text, true);
            }
            return;
        };
        let (parts, leading, trailing) = split_on_ifs(&text, ifs);
        if leading || parts.is_empty() && !text.is_empty() {
            self.end();
        }
        for (i, part) in parts.into_iter().enumerate() {
            if i > 0 {
                self.end();
            }
            self.push(part, true);
        }
        if trailing {
            self.end();
        }
    }

    fn finish(mut self) -> Vec<Vec<Segment>> {
        self.end();
        self.done
    }
}

/// A word's segments as a glob pattern, if any unquoted part of it has glob
/// characters. (`**.ext` stands for `**/*.ext`, so that `**` goes down the
/// directories.)
fn glob_pattern(field: &[Segment]) -> Option<String> {
    if !field.iter().any(|(text, globbable)| *globbable && text.contains(['*', '?', '['])) {
        return None;
    }
    let mut pattern = String::new();
    for (text, globbable) in field {
        if *globbable {
            let mut rest = text.as_str();
            while let Some(i) = rest.find("**") {
                pattern.push_str(&rest[..i + 2]);
                rest = &rest[i + 2..];
                if !rest.starts_with('/') && !rest.is_empty() {
                    pattern.push_str("/*");
                }
            }
            pattern.push_str(rest);
        } else {
            pattern.push_str(&glob::Pattern::escape(text));
        }
    }
    Some(pattern)
}

/// Glob-expand a word (if it has glob characters and matches anything).
fn glob_field(field: Vec<Segment>) -> Vec<String> {
    if let Some(pattern) = glob_pattern(&field) {
        let options = glob::MatchOptions { require_literal_leading_dot: true, ..Default::default() };
        if let Ok(paths) = glob::glob_with(&pattern, options) {
            let matches: Vec<String> = paths.flatten().map(|p| p.to_string_lossy().into_owned()).collect();
            if !matches.is_empty() {
                return matches;
            }
        }
    }
    vec![field.into_iter().map(|(text, _)| text).collect()]
}

impl Shell {
    /// A parsed word, expanded into the argument words it stands for.
    pub(crate) async fn expand_words(self: &Rc<Self>, word: &str) -> Result<Vec<String>> {
        let mut fields = Fields::default();
        self.expand_pieces(&parse_word(word)?, false, true, &mut fields).await?;
        Ok(fields.finish().into_iter().flat_map(glob_field).collect())
    }

    /// A word expanded into one text: neither split nor globbed (as an
    /// assignment's value, or a parameter's default).
    pub(crate) async fn expand_string(self: &Rc<Self>, word: &str) -> Result<String> {
        let mut fields = Fields::default();
        self.expand_pieces(&parse_word(word)?, false, false, &mut fields).await?;
        let text = fields.finish().into_iter().flatten().map(|(text, _)| text);
        Ok(text.collect())
    }

    async fn expand_pieces(
        self: &Rc<Self>,
        pieces: &[WordPieceWithSource],
        quoted: bool,
        split: bool,
        fields: &mut Fields,
    ) -> Result<()> {
        for piece in pieces {
            match &piece.piece {
                WordPiece::Text(text) => fields.push(text.clone(), !quoted),
                WordPiece::SingleQuotedText(text) => fields.push(text.clone(), false),
                WordPiece::AnsiCQuotedText(text) => fields.push(ansi_c_unescape(text), false),
                WordPiece::EscapeSequence(seq) => fields.push(unescape(seq, quoted), false),
                WordPiece::DoubleQuotedSequence(inner) | WordPiece::GettextDoubleQuotedSequence(inner) => {
                    fields.push(String::new(), false);
                    Box::pin(self.expand_pieces(inner, true, split, fields)).await?;
                }
                WordPiece::TildeExpansion(tilde) => fields.push(self.expand_tilde(tilde)?, false),
                WordPiece::ParameterExpansion(expr) => {
                    let value = Box::pin(self.expand_parameter(expr)).await?;
                    fields.expansion(value, quoted, None);
                }
                WordPiece::CommandSubstitution(command) | WordPiece::BackquotedCommandSubstitution(command) => {
                    let command = match &piece.piece {
                        // In backquotes, `\``, `\$` and `\\` stand for themselves.
                        WordPiece::BackquotedCommandSubstitution(_) => {
                            command.replace("\\`", "`").replace("\\$", "$").replace("\\\\", "\\")
                        }
                        _ => command.clone(),
                    };
                    let result = Box::pin(self.run_substitution(&command)).await?;
                    let ifs = self.lookup("IFS");
                    fields.expansion(result, quoted, split.then_some(ifs.as_deref()));
                }
                WordPiece::ArithmeticExpression(_) => return Err(not_implemented("arithmetic expansion $((…))")),
            }
        }
        Ok(())
    }

    fn expand_tilde(&self, tilde: &TildeExpr) -> Result<String> {
        Ok(match tilde {
            TildeExpr::Home => self.lookup("HOME").unwrap_or_else(|| home().to_string_lossy().into_owned()),
            TildeExpr::UserHome(user) => {
                user_home(user).map_or_else(|| format!("~{user}"), |h| h.to_string_lossy().into_owned())
            }
            TildeExpr::WorkingDir => crate::util::cwd().to_string_lossy().into_owned(),
            TildeExpr::OldWorkingDir => self.lookup("OLDPWD").unwrap_or_else(|| "~-".into()),
            _ => return Err(not_implemented("the directory stack (~N)")),
        })
    }

    fn parameter_value(&self, parameter: &Parameter, indirect: bool) -> Result<Option<String>> {
        if indirect {
            return Err(not_implemented("indirect parameters (${!NAME})"));
        }
        match parameter {
            Parameter::Named(name) => Ok(self.lookup(name)),
            other => Err(not_implemented(format!("the parameter {other}"))),
        }
    }

    async fn expand_parameter(self: &Rc<Self>, expr: &ParameterExpr) -> Result<String> {
        let missing = |value: &Option<String>, test: &ParameterTestType| match test {
            ParameterTestType::UnsetOrNull => value.as_deref().is_none_or(str::is_empty),
            ParameterTestType::Unset => value.is_none(),
        };
        Ok(match expr {
            ParameterExpr::Parameter { parameter, indirect } => {
                self.parameter_value(parameter, *indirect)?.unwrap_or_default()
            }
            ParameterExpr::UseDefaultValues { parameter, indirect, test_type, default_value } => {
                let value = self.parameter_value(parameter, *indirect)?;
                if missing(&value, test_type) {
                    self.expand_string(default_value.as_deref().unwrap_or_default()).await?
                } else {
                    value.unwrap_or_default()
                }
            }
            ParameterExpr::UseAlternativeValue { parameter, indirect, test_type, alternative_value } => {
                let value = self.parameter_value(parameter, *indirect)?;
                if missing(&value, test_type) {
                    String::new()
                } else {
                    self.expand_string(alternative_value.as_deref().unwrap_or_default()).await?
                }
            }
            ParameterExpr::IndicateErrorIfNullOrUnset { parameter, indirect, test_type, error_message } => {
                let value = self.parameter_value(parameter, *indirect)?;
                if missing(&value, test_type) {
                    let message = match error_message {
                        Some(m) => self.expand_string(m).await?,
                        None => "parameter null or not set".into(),
                    };
                    bail!("{parameter}: {message}");
                }
                value.unwrap_or_default()
            }
            ParameterExpr::ParameterLength { parameter, indirect } => {
                let value = self.parameter_value(parameter, *indirect)?;
                value.unwrap_or_default().chars().count().to_string()
            }
            _ => return Err(not_implemented("this parameter expansion")),
        })
    }

    /// A redirection, its target expanded: the target is one file name
    /// (bash errors on more, as here).
    pub(crate) async fn expand_redirect(self: &Rc<Self>, redirect: &ast::IoRedirect) -> Result<Vec<Redirect>> {
        use ast::{IoFileRedirectKind as Kind, IoFileRedirectTarget as Target};
        let one_file = async |word: &ast::Word| -> Result<String> {
            let words = self.expand_words(&word.value).await?;
            match <[String; 1]>::try_from(words) {
                Ok([file]) => Ok(file),
                Err(_) => bail!("Bad redirection: {:?} is not one file name", word.value),
            }
        };
        Ok(match redirect {
            ast::IoRedirect::File(fd, kind, target) => {
                let (default_fd, mode) = match kind {
                    Kind::Read | Kind::DuplicateInput => (0, OpenMode::Read),
                    Kind::Write | Kind::Clobber | Kind::DuplicateOutput => (1, OpenMode::Write),
                    Kind::Append => (1, OpenMode::Append),
                    Kind::ReadAndWrite => (0, OpenMode::ReadWrite),
                };
                let fd = fd.unwrap_or(default_fd);
                match target {
                    Target::Filename(word) => vec![Redirect::Open { fd, path: one_file(word).await?, mode }],
                    Target::Fd(from) => vec![Redirect::Dup { fd, from: *from }],
                    Target::Duplicate(word) => {
                        let target = one_file(word).await?;
                        match target.parse::<i32>() {
                            Ok(from) => vec![Redirect::Dup { fd, from }],
                            Err(_) if target == "-" => return Err(not_implemented("closing a file descriptor (>&-)")),
                            // `>&file` is `&>file`.
                            Err(_) if matches!(kind, Kind::DuplicateOutput) && fd == 1 => vec![
                                Redirect::Open { fd: 1, path: target, mode: OpenMode::Write },
                                Redirect::Dup { fd: 2, from: 1 },
                            ],
                            Err(_) => bail!("{target}: ambiguous redirect"),
                        }
                    }
                    Target::ProcessSubstitution(..) => return Err(not_implemented("process substitution")),
                }
            }
            ast::IoRedirect::OutputAndError(word, append) => {
                let mode = if *append { OpenMode::Append } else { OpenMode::Write };
                vec![Redirect::Open { fd: 1, path: one_file(word).await?, mode }, Redirect::Dup { fd: 2, from: 1 }]
            }
            ast::IoRedirect::HereDocument(..) => return Err(not_implemented("here-documents")),
            ast::IoRedirect::HereString(..) => return Err(not_implemented("here-strings")),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_like_bash() {
        assert_eq!(split_on_ifs(" a  b\n", None), (vec!["a".into(), "b".into()], true, true));
        assert_eq!(split_on_ifs("a:b", Some(":")), (vec!["a:b".into()], false, false));
    }

    #[test]
    fn fields_vanish_and_split() {
        let mut f = Fields::default();
        f.push("x".into(), true);
        f.expansion("a b".into(), false, Some(None));
        f.end();
        f.expansion(String::new(), false, Some(None));
        f.push(String::new(), false);
        let words: Vec<String> = f.finish().into_iter().map(|w| w.into_iter().map(|s| s.0).collect()).collect();
        assert_eq!(words, vec!["xa", "b", ""]);
    }

    #[test]
    fn unescapes() {
        assert_eq!(ansi_c_unescape(r"a\tb\x41é\101\q"), "a\tbAéA\\q");
        assert_eq!(unescape("\\*", false), "*");
        assert_eq!(unescape("\\n", true), "\\n");
        assert_eq!(unescape("\\$", true), "$");
    }

    #[test]
    fn glob_patterns() {
        assert_eq!(glob_pattern(&[("**.rs".into(), true)]).as_deref(), Some("**/*.rs"));
        assert_eq!(glob_pattern(&[("a*".into(), false)]), None);
        assert_eq!(glob_pattern(&[("[x]".into(), false), ("*".into(), true)]).as_deref(), Some("[[]x[]]*"));
    }

    #[test]
    fn env_vars() {
        let lookup = |n: &str| (n == "A").then(|| "1".to_owned());
        assert_eq!(expand_env_vars("$A-${A}-$B", &lookup), "1-1-");
    }
}

//! The command history: ~/.config/cq/history.jsonl, one JSON entry per line,
//! shared by every shell (each appends to it).

use std::io::Write;
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::util::home;

pub fn history_file() -> PathBuf {
    home().join(".config").join("cq").join("history.jsonl")
}

#[derive(Clone, Debug)]
pub struct HistoryEntry {
    pub id: String,
    pub text: String,
    /// The working directory it was submitted in.
    pub dir: Option<String>,
}

impl HistoryEntry {
    fn to_json(&self) -> Value {
        let mut entry = json!({ "id": self.id, "text": self.text });
        if let Some(dir) = &self.dir {
            entry["dir"] = json!(dir);
        }
        entry
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Prev,
    Next,
}

/// The lines of the history file (blank ones left out).
fn read_lines() -> std::io::Result<Vec<String>> {
    Ok(std::fs::read_to_string(history_file())?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect())
}

pub struct ShellHistory {
    entries: Vec<HistoryEntry>,
    /// How many entries are kept, in the file and here (see set_limit).
    limit: usize,
    /// How many lines the file has, as far as we know (other shells append
    /// to it too).
    file_lines: usize,
}

impl ShellHistory {
    pub fn load() -> Self {
        let lines = read_lines().unwrap_or_default();
        let entries = lines
            .iter()
            .enumerate()
            .filter_map(|(i, line)| {
                let entry: Value = serde_json::from_str(line).ok()?;
                let text = entry.get("text")?.as_str()?.to_owned();
                let id = match entry.get("id").and_then(Value::as_str) {
                    Some(id) if !id.is_empty() => id.to_owned(),
                    _ => format!("__legacy_{i}"),
                };
                let dir = entry.get("dir").and_then(Value::as_str).map(str::to_owned);
                Some(HistoryEntry { id, text, dir })
            })
            .collect();
        Self { entries, limit: usize::MAX, file_lines: lines.len() }
    }

    /// Keep the last `limit` entries only, in the file and here: the oldest
    /// ones go now, and as new ones come.
    pub fn set_limit(&mut self, limit: usize) {
        self.limit = limit;
        self.trim();
    }

    /// Cut the history down to the limit. The file is cut from what it holds
    /// now (other shells may have appended to it since it was read), line by
    /// line, and replaced at once: a shell appending meanwhile writes to the
    /// old file or to the new one, never to half of one.
    fn trim(&mut self) {
        if self.entries.len() > self.limit {
            self.entries.drain(..self.entries.len() - self.limit);
        }
        if self.file_lines <= self.limit {
            return;
        }
        let Ok(lines) = read_lines() else { return };
        let kept = &lines[lines.len().saturating_sub(self.limit)..];
        let file = history_file();
        let tmp = file.with_extension(format!("jsonl.{}.tmp", std::process::id()));
        let content: String = kept.iter().map(|l| format!("{l}\n")).collect();
        if std::fs::write(&tmp, content).and_then(|_| std::fs::rename(&tmp, &file)).is_ok() {
            self.file_lines = kept.len();
        }
    }

    /// Append an entry, skipping consecutive duplicates (the same text, run
    /// in the same place).
    pub fn push(&mut self, entry: HistoryEntry) {
        if let Some(last) = self.entries.last()
            && last.text == entry.text
            && last.dir == entry.dir
        {
            return;
        }
        let file = history_file();
        let appended = (|| -> std::io::Result<()> {
            if let Some(dir) = file.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&file)?;
            f.write_all(format!("{}\n", entry.to_json()).as_bytes())
        })();
        if appended.is_ok() {
            self.file_lines += 1;
        }
        self.entries.push(entry);
        self.trim();
    }

    /// The most recent entry's text that extends `text`, if any.
    pub fn filigrane(&self, text: &str) -> Option<String> {
        if text.is_empty() {
            return None;
        }
        self.entries
            .iter()
            .rev()
            .find(|e| e.text.starts_with(text) && e.text.len() > text.len())
            .map(|e| e.text.clone())
    }

    /// Find the previous/next entry relative to `anchor_id`, among those
    /// containing `filter`: its text and id. Runs of consecutive identical
    /// texts count as one entry, so that navigating doesn't stop twice on
    /// the same command (ls -a; ls -l; ls -l; ls -a walks over one ls -l).
    pub fn navigate(
        &self,
        direction: Direction,
        anchor_id: Option<&str>,
        filter: &str,
    ) -> Option<(String, String)> {
        let relevant: Vec<&HistoryEntry> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(i, e)| *i == 0 || self.entries[i - 1].text != e.text)
            .map(|(_, e)| e)
            .collect();
        let anchor = anchor_id
            .and_then(|id| relevant.iter().position(|e| e.id == id))
            .unwrap_or(relevant.len());
        let matches = |e: &&&HistoryEntry| filter.is_empty() || e.text.contains(filter);
        let found = match direction {
            Direction::Prev => relevant[..anchor].iter().rev().find(matches),
            Direction::Next => relevant.iter().skip(anchor + 1).find(matches),
        };
        found.map(|e| (e.text.clone(), e.id.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn history(texts: &[&str]) -> ShellHistory {
        let entries = texts
            .iter()
            .enumerate()
            .map(|(i, t)| HistoryEntry { id: i.to_string(), text: (*t).into(), dir: None })
            .collect();
        ShellHistory { entries, limit: usize::MAX, file_lines: 0 }
    }

    #[test]
    fn navigates_with_filter_and_dedup() {
        let h = history(&["ls -a", "ls -l", "ls -l", "git st", "ls -a"]);
        let (t, id) = h.navigate(Direction::Prev, None, "ls").unwrap();
        assert_eq!((t.as_str(), id.as_str()), ("ls -a", "4"));
        let (t, id) = h.navigate(Direction::Prev, Some(&id), "ls").unwrap();
        assert_eq!((t.as_str(), id.as_str()), ("ls -l", "1"));
        let (t, _) = h.navigate(Direction::Next, Some(&id), "ls").unwrap();
        assert_eq!(t, "ls -a");
        assert!(h.navigate(Direction::Next, Some("4"), "").is_none());
    }

    #[test]
    fn filigrane_extends() {
        let h = history(&["echo hello", "echo"]);
        assert_eq!(h.filigrane("ec").as_deref(), Some("echo"));
        assert_eq!(h.filigrane("echo ").as_deref(), Some("echo hello"));
        assert_eq!(h.filigrane("echo hello"), None);
        assert_eq!(h.filigrane(""), None);
    }
}

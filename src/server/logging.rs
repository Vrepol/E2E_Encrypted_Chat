use std::{
    fs::{create_dir_all, File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use chrono::Local;

#[derive(Clone, Default)]
pub(crate) struct ServerLogger {
    file: Option<Arc<Mutex<File>>>,
}

impl ServerLogger {
    pub(crate) fn stdout_only() -> Self {
        Self { file: None }
    }

    pub(crate) fn with_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        Ok(Self {
            file: Some(Arc::new(Mutex::new(file))),
        })
    }

    pub(crate) fn info(&self, scope: &str, message: impl AsRef<str>) {
        self.write("INFO", scope, message.as_ref());
    }

    pub(crate) fn warn(&self, scope: &str, message: impl AsRef<str>) {
        self.write("WARN", scope, message.as_ref());
    }

    pub(crate) fn error(&self, scope: &str, message: impl AsRef<str>) {
        self.write("ERROR", scope, message.as_ref());
    }

    fn write(&self, level: &str, scope: &str, message: &str) {
        let ts = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let line = format!("[{ts}] [{level}] [{scope}] {message}");
        match level {
            "ERROR" => eprintln!("{line}"),
            _ => println!("{line}"),
        }

        if let Some(file) = &self.file {
            if let Ok(mut guard) = file.lock() {
                let _ = writeln!(guard, "{line}");
                let _ = guard.flush();
            }
        }
    }
}

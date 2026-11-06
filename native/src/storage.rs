use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub fn safe(path: &Path) -> Result<(), String> {
    for p in path.ancestors() {
        match std::fs::symlink_metadata(p) {
            Ok(m) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if m.file_attributes() & 0x400 != 0 {
                        return Err("Reparse path refused".into());
                    }
                }
                if m.file_type().is_symlink() {
                    return Err("Symlink refused".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
pub fn read(path: &Path) -> Result<File, String> {
    safe(path)?;
    let mut o = OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(1);
    }
    o.open(path).map_err(|e| e.to_string())
}
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.as_ref().len() * 2);
    for &byte in bytes.as_ref() {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}
pub fn digest(path: &Path) -> Result<(String, u64), String> {
    let mut f = read(path)?;
    let mut h = Sha256::new();
    let mut b = [0u8; 65536];
    let mut len = 0;
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
        len += n as u64
    }
    Ok((hex(h.finalize()), len))
}
pub fn json_file(path: &Path, limit: u64) -> Result<Value, String> {
    let mut f = read(path)?;
    if f.metadata().map_err(|e| e.to_string())?.len() > limit {
        return Err("Metadata exceeds size limit".into());
    }
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    crate::canonical::parse(&bytes)
}
pub fn atomic(path: &Path, value: &Value) -> Result<(), String> {
    safe(path)?;
    let parent = path.parent().ok_or("No parent")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let temp = parent.join(format!(
        ".native-{}-{}.tmp",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos()
    ));
    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        f.write_all(&serde_json::to_vec(value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&temp, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}
pub fn files(directory: &Path, recurse: bool) -> Result<Vec<PathBuf>, String> {
    safe(directory)?;
    if !directory.exists() {
        return Ok(vec![]);
    }
    let mut result = Vec::new();
    let mut pending = vec![(directory.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > 256 {
            return Err("Inventory depth limit exceeded".into());
        }
        for e in std::fs::read_dir(directory).map_err(|e| e.to_string())? {
            let p = e.map_err(|e| e.to_string())?.path();
            safe(&p)?;
            if p.is_dir() {
                if recurse {
                    pending.push((p, depth + 1));
                }
            } else if p.is_file() {
                result.push(p);
                if result.len() > 1_000_000 {
                    return Err("Inventory file limit exceeded".into());
                }
            }
        }
    }
    Ok(result)
}
#[derive(Default)]
pub struct Inventory {
    entries: HashMap<PathBuf, u64>,
    bytes: u64,
}
impl Inventory {
    pub fn reconcile(&mut self, value: &Value) -> Result<Value, String> {
        let path = Path::new(value["path"].as_str().ok_or("Missing path")?);
        let mut next = HashMap::new();
        for file in files(path, value["recurse"].as_bool().unwrap_or(false))? {
            if let Some(ext) = value["extension"].as_str() {
                if !file
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case(ext))
                {
                    continue;
                }
            }
            let size = file.metadata().map_err(|e| e.to_string())?.len();
            next.insert(file, size);
        }
        let mut total = self.bytes as i128;
        let mut changes = 0;
        for (key, old) in &self.entries {
            if !next.contains_key(key) {
                total -= *old as i128;
                changes += 1
            }
        }
        for (key, new) in &next {
            match self.entries.get(key) {
                Some(old) if old == new => {}
                Some(old) => {
                    total += *new as i128 - *old as i128;
                    changes += 1
                }
                None => {
                    total += *new as i128;
                    changes += 1
                }
            }
        }
        if total < 0 || total > u64::MAX as i128 {
            return Err("Capacity counter inconsistency".into());
        }
        self.bytes = total as u64;
        self.entries = next;
        Ok(
            json!({"Files":self.entries.len(),"Bytes":self.bytes,"ChangedFiles":changes,"Reconciled":true}),
        )
    }
}

use crate::{canonical, storage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap},
    fs::OpenOptions,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};
#[derive(Clone)]
struct Entry {
    at: String,
    tick: i128,
    score: i64,
    version: u64,
}
#[derive(Default)]
pub struct Journal {
    path: PathBuf,
    mode: String,
    entries: HashMap<String, Entry>,
    expiry: BinaryHeap<Reverse<(i128, u64, String)>>,
    version: u64,
    frames: u64,
    last: String,
    bytes: u64,
}
fn time(v: &Value, key: &str) -> Result<String, String> {
    let at = v[key].as_str().ok_or("Dedupe timestamp missing")?;
    canonical::ticks(at)?;
    Ok(at.into())
}
fn score(v: &Value) -> Result<i64, String> {
    if v.is_null() {
        Ok(0)
    } else {
        v.as_i64().ok_or("Invalid dedupe score".into())
    }
}
fn frame_hash(previous: &str, payload: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(previous.as_bytes());
    h.update(b"\n");
    h.update(payload);
    storage::hex(h.finalize())
}
impl Journal {
    fn set(&mut self, key: String, at: String, score: i64) -> Result<(), String> {
        if key.len() > 512 || key.is_empty() {
            return Err("Invalid dedupe key".into());
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= 100000 {
            return Err("Dedupe entry bound exceeded".into());
        }
        let tick = canonical::ticks(&at)?;
        self.version = self
            .version
            .checked_add(1)
            .ok_or("Dedupe version overflow")?;
        self.entries.insert(
            key.clone(),
            Entry {
                at,
                tick,
                score,
                version: self.version,
            },
        );
        self.expiry.push(Reverse((tick, self.version, key)));
        if self.entries.len() > 100000 {
            return Err("Dedupe entry bound exceeded".into());
        }
        Ok(())
    }
    fn wal(&self) -> PathBuf {
        self.path.with_file_name(format!(
            "{}.wal",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("invalid")
        ))
    }
    fn fields(&self) -> (&str, &str) {
        if self.mode == "path" {
            ("Key", "LastQueued")
        } else {
            ("SHA256", "LastCompleted")
        }
    }
    fn prune(&mut self, now: i128, age: i128) -> Vec<String> {
        let mut removed = Vec::new();
        while let Some(Reverse((at, version, key))) = self.expiry.peek().cloned() {
            if self.entries.get(&key).is_none_or(|e| e.version != version) {
                self.expiry.pop();
                continue;
            }
            if now - at <= age {
                break;
            }
            self.expiry.pop();
            self.entries.remove(&key);
            removed.push(key)
        }
        if self.expiry.len() > 4 * self.entries.len() + 64 {
            self.expiry = self
                .entries
                .iter()
                .map(|(k, e)| Reverse((e.tick, e.version, k.clone())))
                .collect()
        }
        removed
    }
    pub fn open(v: &Value) -> Result<Self, String> {
        let path = PathBuf::from(v["path"].as_str().ok_or("Missing journal path")?);
        storage::safe(&path)?;
        let mode = v["mode"]
            .as_str()
            .filter(|x| matches!(*x, "path" | "hash"))
            .ok_or("Invalid journal mode")?
            .to_string();
        let mut s = Self {
            path,
            mode,
            last: "GENESIS".into(),
            ..Self::default()
        };
        let (key_field, time_field) = s.fields();
        let (key_field, time_field) = (key_field.to_string(), time_field.to_string());
        if s.path.exists() {
            let base = storage::json_file(&s.path, 16 * 1024 * 1024)?;
            let rows = if base.is_null() {
                vec![]
            } else if let Some(rows) = base.as_array() {
                rows.clone()
            } else {
                vec![base]
            };
            for row in rows {
                if let Some(key) = row[&key_field].as_str() {
                    s.set(key.into(), time(&row, &time_field)?, score(&row["Score"])?)?
                }
            }
        }
        let wal = s.wal();
        if wal.exists() {
            let file = storage::read(&wal)?;
            s.bytes = file.metadata().map_err(|e| e.to_string())?.len();
            if s.bytes > 4 * 1024 * 1024 {
                return Err("Dedupe WAL exceeds recovery bound".into());
            }
            let mut reader = BufReader::new(file);
            let mut line = Vec::new();
            loop {
                line.clear();
                if reader
                    .read_until(b'\n', &mut line)
                    .map_err(|e| e.to_string())?
                    == 0
                {
                    break;
                }
                if line.pop() != Some(b'\n') || line.is_empty() {
                    return Err("Incomplete or empty dedupe WAL frame".into());
                }
                if line.len() > 65536 {
                    return Err("Oversized dedupe frame".into());
                }
                let envelope = canonical::parse(&line)?;
                let payload = envelope["Payload"]
                    .as_str()
                    .ok_or("Missing dedupe payload")?;
                let previous = envelope["Previous"]
                    .as_str()
                    .ok_or("Missing dedupe chain")?;
                let digest = envelope["SHA256"].as_str().ok_or("Missing dedupe digest")?;
                if previous != s.last || frame_hash(previous, payload.as_bytes()) != digest {
                    return Err("Dedupe WAL checksum/sequence mismatch".into());
                }
                let row = canonical::parse(payload.as_bytes())?;
                if row["Schema"].as_u64() != Some(1)
                    || row["Mode"].as_str() != Some(s.mode.as_str())
                    || row["Sequence"].as_u64() != Some(s.frames + 1)
                {
                    return Err("Dedupe WAL schema/sequence mismatch".into());
                }
                s.set(
                    row["Key"].as_str().ok_or("Missing dedupe key")?.into(),
                    time(&row, "At")?,
                    score(&row["Score"])?,
                )?;
                s.last = digest.into();
                s.frames += 1;
            }
        }
        let now = canonical::ticks(v["now"].as_str().ok_or("Missing current time")?)?;
        let age = v["max_age"]
            .as_i64()
            .filter(|x| *x > 0)
            .ok_or("Invalid dedupe retention")? as i128
            * 10_000_000;
        s.prune(now, age);
        s.entries.retain(|_, e| e.tick <= now + 50_000_000);
        Ok(s)
    }
    pub fn rows(&self) -> Value {
        let (key, time) = self.fields();
        Value::Array(
            self.entries
                .iter()
                .map(|(k, e)| {
                    let mut row = serde_json::Map::new();
                    row.insert(key.into(), k.clone().into());
                    row.insert(time.into(), e.at.clone().into());
                    if self.mode == "path" {
                        row.insert("Score".into(), e.score.into());
                    }
                    Value::Object(row)
                })
                .collect(),
        )
    }
    pub fn put(&mut self, v: &Value) -> Result<Value, String> {
        let now = canonical::ticks(v["now"].as_str().ok_or("Missing now")?)?;
        let age = v["max_age"]
            .as_i64()
            .filter(|x| *x > 0)
            .ok_or("Invalid retention")? as i128
            * 10_000_000;
        let at = time(v, "at")?;
        if canonical::ticks(&at)? > now + 50_000_000 {
            return Err("Dedupe completion is in the future".into());
        }
        let key = v["key"].as_str().ok_or("Missing dedupe key")?;
        if key.is_empty() || key.len() > 512 {
            return Err("Invalid key".into());
        }
        let score = score(&v["score"])?;
        let expired = self.prune(now, age);
        if !self.entries.contains_key(key) && self.entries.len() >= 100000 {
            return Err("Dedupe entry bound exceeded".into());
        }
        let sequence = self
            .frames
            .checked_add(1)
            .ok_or("Journal sequence overflow")?;
        let payload=serde_json::to_string(&json!({"Schema":1,"Mode":self.mode,"Sequence":sequence,"Key":key,"At":at,"Score":score})).map_err(|e|e.to_string())?;
        let digest = frame_hash(&self.last, payload.as_bytes());
        let mut bytes =
            serde_json::to_vec(&json!({"Previous":self.last,"SHA256":digest,"Payload":payload}))
                .map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let wal = self.wal();
        storage::safe(&wal)?;
        std::fs::create_dir_all(wal.parent().ok_or("Missing parent")?)
            .map_err(|e| e.to_string())?;
        let actual = if wal.exists() {
            wal.metadata().map_err(|e| e.to_string())?.len()
        } else {
            0
        };
        if actual != self.bytes {
            return Err("Dedupe WAL changed outside its owner; reload before writing".into());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(&wal)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        self.frames = sequence;
        self.bytes += bytes.len() as u64;
        self.last = digest;
        self.set(key.into(), at, score)?;
        let compact = self.frames >= 128 || self.bytes >= 1024 * 1024;
        if compact {
            storage::atomic(&self.path, &self.rows())?;
            let empty = wal.with_extension("wal.empty");
            storage::safe(&empty)?;
            // A crash after creating the empty replacement is recoverable. Never
            // discard a nonempty file or follow a reparse point here.
            if empty.exists() {
                if storage::read(&empty)?
                    .metadata()
                    .map_err(|e| e.to_string())?
                    .len()
                    != 0
                {
                    return Err("Unexpected nonempty WAL replacement".into());
                }
                std::fs::remove_file(&empty).map_err(|e| e.to_string())?;
            }
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&empty)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            drop(file);
            std::fs::rename(&empty, &wal).map_err(|e| e.to_string())?;
            self.frames = 0;
            self.bytes = 0;
            self.last = "GENESIS".into();
        }
        Ok(
            json!({"ExpiredKeys":expired,"Compacted":compact,"WalBytes":self.bytes,"Entries":self.entries.len()}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_tail_cannot_be_replayed_as_success() {
        let root = std::env::temp_dir().join(format!("sentinel-wal-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("dedupe.json");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_file_name("dedupe.json.wal"));
        let args = json!({"path":path,"mode":"hash","now":"2026-11-06T00:00:00Z","max_age":3600});
        let mut s = Journal::open(&args).unwrap();
        let mut put = args.clone();
        put["key"] = "A".into();
        put["at"] = "2026-11-06T00:00:00Z".into();
        s.put(&put).unwrap();
        assert_eq!(Journal::open(&args).unwrap().entries.len(), 1);
        let mut f = OpenOptions::new().append(true).open(s.wal()).unwrap();
        f.write_all(b"{\"partial\"").unwrap();
        drop(f);
        assert!(Journal::open(&args).is_err());
        let _ = std::fs::remove_file(s.wal());
        let _ = std::fs::remove_dir(&root);
    }
}

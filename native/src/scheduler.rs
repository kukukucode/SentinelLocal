use crate::{canonical, storage};
use serde_json::{json, Value};
use std::{
    cmp::Reverse,
    collections::{BinaryHeap, HashMap, HashSet},
    io::Read,
    path::Path,
    time::UNIX_EPOCH,
};
#[derive(Clone)]
struct Request {
    sha: String,
    version: u64,
    created: i128,
    queued: i128,
    available: i128,
    lane: String,
    name: String,
}
type Item = Reverse<(i128, String, u64, String)>;
#[derive(Default)]
pub struct Scheduler {
    items: HashMap<String, Request>,
    ready: HashMap<String, BinaryHeap<Item>>,
    delayed: BinaryHeap<Item>,
    version: u64,
    last_now: Option<i128>,
}
impl Scheduler {
    fn rebuild(&mut self, now: i128) {
        self.delayed.clear();
        self.ready.clear();
        let keys: Vec<_> = self.items.keys().cloned().collect();
        for key in keys {
            let r = &self.items[&key];
            if r.available > now {
                self.delayed.push(Reverse((
                    r.available,
                    r.name.clone(),
                    r.version,
                    key.clone(),
                )))
            } else {
                self.add_ready(&key)
            }
        }
    }
    fn add_ready(&mut self, key: &str) {
        let r = &self.items[key];
        self.ready.entry(r.lane.clone()).or_default().push(Reverse((
            r.created,
            r.name.clone(),
            r.version,
            key.into(),
        )));
    }
    fn peek(&mut self, lane: &str) -> Option<String> {
        let heap = self.ready.entry(lane.into()).or_default();
        while let Some(Reverse((_, _, version, key))) = heap.peek() {
            if self.items.get(key).is_some_and(|r| r.version == *version) {
                return Some(key.clone());
            }
            heap.pop();
        }
        None
    }
    pub fn choose(&mut self, v: &Value) -> Result<Value, String> {
        let root = Path::new(v["path"].as_str().ok_or("Missing queue root")?);
        let now = canonical::ticks(v["now"].as_str().ok_or("Missing current time")?)?;
        let mut seen = HashSet::new();
        for lane in ["high", "normal"] {
            for path in storage::files(&root.join(lane), false)? {
                if !path
                    .extension()
                    .and_then(|x| x.to_str())
                    .is_some_and(|s| s.eq_ignore_ascii_case("json"))
                {
                    continue;
                }
                let key = path.to_str().ok_or("Non Unicode path")?.to_string();
                seen.insert(key.clone());
                if seen.len() > 10000 {
                    return Err("Scheduler inventory bound exceeded".into());
                }
                let mut file = storage::read(&path)?;
                let m = file.metadata().map_err(|e| e.to_string())?;
                let size = m.len();
                if size > 4 * 1024 * 1024 {
                    return Err("Request metadata too large".into());
                }
                let created = m
                    .created()
                    .map_err(|e| e.to_string())?
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_nanos() as i128
                    / 100;
                let mut bytes = Vec::with_capacity(size as usize);
                file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                use sha2::Digest;
                let sha = storage::hex(sha2::Sha256::digest(&bytes));
                if self
                    .items
                    .get(&key)
                    .is_some_and(|r| r.sha == sha && r.created == created)
                {
                    continue;
                }
                let parsed = canonical::parse(&bytes);
                let (mut queued, mut available) = (created, 0);
                if let Ok(p) = parsed {
                    let result = (|| -> Result<(i128, i128), String> {
                        let q = if let Some(s) = p["QueuedAt"].as_str().filter(|s| !s.is_empty()) {
                            canonical::ticks(s)?
                        } else {
                            created
                        };
                        let a = if let Some(s) =
                            p["AvailableAfter"].as_str().filter(|s| !s.is_empty())
                        {
                            canonical::ticks(s)?
                        } else {
                            0
                        };
                        Ok((q, a))
                    })();
                    if let Ok((q, a)) = result {
                        queued = q;
                        available = a
                    }
                }
                self.version = self
                    .version
                    .checked_add(1)
                    .ok_or("Scheduler version overflow")?;
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("Invalid name")?
                    .to_string();
                let r = Request {
                    sha,
                    version: self.version,
                    created,
                    queued,
                    available,
                    lane: lane.into(),
                    name: name.clone(),
                };
                self.items.insert(key.clone(), r);
                if available > now {
                    self.delayed
                        .push(Reverse((available, name, self.version, key)))
                } else {
                    self.add_ready(&key)
                }
            }
        }
        self.items.retain(|k, _| seen.contains(k));
        while let Some(Reverse((at, _, version, key))) = self.delayed.peek().cloned() {
            if at > now {
                break;
            }
            self.delayed.pop();
            if self.items.get(&key).is_some_and(|r| r.version == version) {
                self.add_ready(&key)
            }
        }
        if self.last_now.is_some_and(|previous| now < previous) {
            self.rebuild(now)
        }
        self.last_now = Some(now);
        let high = self.peek("high");
        let normal = self.peek("normal");
        let promote = normal.as_ref().is_some_and(|k| {
            v["high_burst"].as_u64().unwrap_or(0) >= v["burst_limit"].as_u64().unwrap_or(0)
                && now - self.items[k].queued
                    >= v["aging_seconds"].as_i64().unwrap_or(0) as i128 * 10_000_000
        });
        let chosen = if promote { normal } else { high.or(normal) };
        if self.delayed.len() + self.ready.values().map(BinaryHeap::len).sum::<usize>()
            > 4 * self.items.len() + 64
        {
            self.rebuild(now)
        }
        Ok(json!({"Path":chosen,"KnownRequests":self.items.len()}))
    }
}

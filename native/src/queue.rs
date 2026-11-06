use crate::{canonical, storage};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    path::Path,
    sync::Arc,
};
#[derive(Clone)]
struct Unit {
    sha: String,
    count: u64,
    base: u64,
    times: Arc<Vec<String>>,
    reset: bool,
    queued: String,
    pending: u64,
    bytes: u64,
}
#[derive(Default)]
pub struct Catalog {
    units: HashMap<String, Unit>,
    pending: u64,
    bytes: u64,
}
fn number(v: &Value, key: &str) -> Result<u64, String> {
    v[key]
        .as_u64()
        .ok_or_else(|| format!("Invalid queue integer: {key}"))
}
fn parse(bytes: &[u8], sha: String) -> Result<Unit, String> {
    let v = canonical::parse(bytes)?;
    let events = v["Events"].as_array().ok_or("Missing events")?;
    let base = number(&v, "NextIndex")?;
    let reset = v["Reset"].as_bool().ok_or("Missing reset flag")?;
    if v["Schema"].as_u64() != Some(1)
        || events.len() > 1000
        || base > events.len() as u64
        || (events.is_empty() && !reset)
    {
        return Err("Invalid queue unit".into());
    }
    let mut times = Vec::new();
    for event in events {
        if !matches!(
            event["Id"].as_u64(),
            Some(1 | 3 | 4 | 16 | 19 | 20 | 21 | 22 | 25 | 255)
        ) || !event["RecordId"]
            .as_u64()
            .is_some_and(|x| x > 0 && x <= i64::MAX as u64)
            || event["Xml"].as_str().is_none_or(|s| s.is_empty())
        {
            return Err("Invalid queued event".into());
        }
        let t = event["TimeCreated"]
            .as_str()
            .ok_or("Invalid queued timestamp")?;
        canonical::ticks(t)?;
        times.push(t.into());
    }
    let queued = v["QueuedAt"]
        .as_str()
        .ok_or("Missing queued time")?
        .to_string();
    canonical::ticks(&queued)?;
    Ok(Unit {
        sha,
        count: events.len() as u64,
        base,
        times: Arc::new(times),
        reset,
        queued,
        pending: events.len() as u64 - base,
        bytes: bytes.len() as u64,
    })
}
impl Catalog {
    pub fn state(&mut self, root: &Path) -> Result<Value, String> {
        let directory = root.join("state/sysmon-analysis");
        let mut seen = HashSet::new();
        let mut oldest: Option<(i128, String)> = None;
        let mut total_read = 0u64;
        let mut parsed = 0;
        let mut next = self.units.clone();
        for lane in ["pending", "processing"] {
            let files = storage::files(&directory.join(lane), false)?;
            for path in &files {
                let name = path
                    .file_name()
                    .and_then(|x| x.to_str())
                    .ok_or("Invalid queue name")?;
                if name.to_ascii_lowercase().ends_with(".json.progress") {
                    let payload = path.with_file_name(
                        name.strip_suffix(".progress")
                            .ok_or("Invalid progress name")?,
                    );
                    if !payload.is_file() {
                        return Err("Orphan analysis progress".into());
                    }
                    continue;
                }
                if !name.to_ascii_lowercase().ends_with(".json") {
                    continue;
                }
                let stem = name.strip_suffix(".json").ok_or("Invalid queue name")?;
                let parts: Vec<_> = stem.split('-').collect();
                if parts.len() != 2
                    || parts[0].len() != 20
                    || !parts[0].bytes().all(|x| x.is_ascii_digit())
                    || parts[1].len() != 24
                    || !parts[1]
                        .bytes()
                        .all(|x| x.is_ascii_digit() || (b'A'..=b'F').contains(&x))
                {
                    return Err("Unsafe analysis name".into());
                }
                let key = path.to_str().ok_or("Non Unicode queue path")?.to_string();
                seen.insert(key.clone());
                if seen.len() > 10000 {
                    return Err("Queue inventory exceeds safety bound".into());
                }
                let mut file = storage::read(path)?;
                let size = file.metadata().map_err(|e| e.to_string())?.len();
                if size > 64 * 1024 * 1024 {
                    return Err("Oversized queue unit".into());
                }
                total_read = total_read.checked_add(size).ok_or("Queue byte overflow")?;
                if total_read > 256 * 1024 * 1024 {
                    return Err("Queue inventory exceeds 256 MiB safety bound".into());
                }
                let mut bytes = Vec::with_capacity(size as usize);
                file.read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                use sha2::Digest;
                let sha = storage::hex(sha2::Sha256::digest(&bytes));
                let mut unit = match self.units.get(&key) {
                    Some(u) if u.sha == sha => u.clone(),
                    _ => {
                        parsed += 1;
                        parse(&bytes, sha)?
                    }
                };
                unit.bytes = size;
                let mut index = unit.base;
                let progress = path.with_file_name(format!("{name}.progress"));
                if progress.exists() {
                    let p = storage::json_file(&progress, 4096)?;
                    index = number(&p, "NextIndex")?;
                    if p["Schema"].as_u64() != Some(1)
                        || p["UnitName"].as_str() != Some(name)
                        || !p["PayloadSHA256"]
                            .as_str()
                            .is_some_and(|s| s.eq_ignore_ascii_case(&unit.sha))
                        || number(&p, "EventCount")? != unit.count
                        || index < unit.base
                        || index > unit.count
                    {
                        return Err("Progress does not match immutable payload".into());
                    }
                    unit.bytes += progress.metadata().map_err(|e| e.to_string())?.len();
                }
                unit.pending = unit.count - index;
                let at = if index < unit.count {
                    Some(unit.times[index as usize].clone())
                } else if unit.count == 0 && unit.reset {
                    Some(unit.queued.clone())
                } else {
                    None
                };
                if let Some(at) = at {
                    let tick = canonical::ticks(&at)?;
                    if oldest.as_ref().is_none_or(|(t, _)| tick < *t) {
                        oldest = Some((tick, at));
                    }
                }
                next.insert(key, unit);
            }
        }
        next.retain(|key, _| seen.contains(key));
        // Aggregate only changed units; byte digests are still rechecked on every query.
        let mut pending = self.pending as i128;
        let mut bytes = self.bytes as i128;
        for (key, old) in &self.units {
            if !next.contains_key(key) {
                pending -= old.pending as i128;
                bytes -= old.bytes as i128;
            }
        }
        for (key, new) in &next {
            match self.units.get(key) {
                Some(old) => {
                    pending += new.pending as i128 - old.pending as i128;
                    bytes += new.bytes as i128 - old.bytes as i128
                }
                None => {
                    pending += new.pending as i128;
                    bytes += new.bytes as i128
                }
            }
        }
        if pending < 0 || bytes < 0 || pending > u64::MAX as i128 || bytes > u64::MAX as i128 {
            return Err("Queue totals inconsistent".into());
        }
        self.pending = pending as u64;
        self.bytes = bytes as u64;
        self.units = next;
        Ok(
            json!({"PendingEvents":self.pending,"Units":self.units.len(),"Bytes":self.bytes,"OldestEventAt":oldest.map(|(_,s)|s),"ParsedUnits":parsed,"ValidatedPayloadBytes":total_read}),
        )
    }
}

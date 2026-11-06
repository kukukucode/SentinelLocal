use serde_json::{json, Value};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};

#[derive(Default)]
struct Expiry {
    values: HashMap<String, (i128, u64)>,
    heap: BinaryHeap<Reverse<(i128, u64, String)>>,
    version: u64,
}
impl Expiry {
    fn set(&mut self, key: String, at: i128) -> Result<(), String> {
        let key = key.to_ascii_lowercase();
        self.version = self
            .version
            .checked_add(1)
            .ok_or("Expiry version overflow")?;
        self.values.insert(key.clone(), (at, self.version));
        self.heap.push(Reverse((at, self.version, key)));
        if self.heap.len() > 4 * self.values.len() + 64 {
            self.heap = self
                .values
                .iter()
                .map(|(k, (t, v))| Reverse((*t, *v, k.clone())))
                .collect()
        }
        Ok(())
    }
    fn remove_first(&mut self, before: Option<i128>) -> Option<String> {
        while let Some(Reverse((t, v, k))) = self.heap.peek().cloned() {
            if self.values.get(&k) != Some(&(t, v)) {
                self.heap.pop();
                continue;
            }
            if before.is_some_and(|b| t >= b) {
                return None;
            }
            self.heap.pop();
            self.values.remove(&k);
            return Some(k);
        }
        None
    }
}
#[derive(Default)]
struct Lru {
    values: HashMap<String, u64>,
    order: VecDeque<(String, u64)>,
    version: u64,
}
impl Lru {
    fn touch(&mut self, key: String, limit: usize) -> Result<Vec<String>, String> {
        self.version = self.version.checked_add(1).ok_or("LRU version overflow")?;
        self.values.insert(key.clone(), self.version);
        self.order.push_back((key, self.version));
        let mut evicted = Vec::new();
        while self.values.len() > limit {
            let (k, v) = self.order.pop_front().ok_or("LRU state inconsistent")?;
            if self.values.get(&k) == Some(&v) {
                self.values.remove(&k);
                evicted.push(k)
            }
        }
        if self.order.len() > 4 * limit + 64 {
            self.order.retain(|(k, v)| self.values.get(k) == Some(v));
        }
        Ok(evicted)
    }
}
#[derive(Default)]
pub struct Engine {
    expiry: HashMap<String, Expiry>,
    lru: HashMap<String, Lru>,
    queues: HashMap<String, crate::queue::Catalog>,
    schedulers: HashMap<String, crate::scheduler::Scheduler>,
    journals: HashMap<String, crate::journal::Journal>,
    inventories: HashMap<String, crate::storage::Inventory>,
}
fn context(v: &Value) -> Result<&str, String> {
    let s = v["context"].as_str().ok_or("Missing context")?;
    if s.len() > 2048 {
        return Err("Context too long".into());
    }
    Ok(s)
}
fn tick(v: &Value) -> Result<i128, String> {
    v.as_str()
        .ok_or("Tick must be a decimal string")?
        .parse()
        .map_err(|_| "Invalid tick".into())
}
impl Engine {
    pub fn execute(&mut self, op: &str, v: &Value) -> Result<Value, String> {
        match op {
            "expiry_reset" => {
                let c = context(v)?;
                if !self.expiry.contains_key(c) && self.expiry.len() >= 64 {
                    return Err("Too many expiry contexts".into());
                }
                let mut e = Expiry::default();
                for row in v["rows"].as_array().ok_or("Missing expiry rows")? {
                    e.set(
                        row["key"].as_str().ok_or("Missing key")?.into(),
                        tick(&row["at"])?,
                    )?
                }
                self.expiry.insert(c.into(), e);
                Ok(json!({"Reset":true}))
            }
            "expiry_set" => {
                let e = self
                    .expiry
                    .get_mut(context(v)?)
                    .ok_or("Expiry context missing")?;
                e.set(
                    v["key"].as_str().ok_or("Missing key")?.into(),
                    tick(&v["at"])?,
                )?;
                Ok(json!({"Count":e.values.len()}))
            }
            "expiry_take" => {
                let e = self
                    .expiry
                    .get_mut(context(v)?)
                    .ok_or("Expiry context missing")?;
                let mut keys = Vec::new();
                while let Some(k) = e.remove_first(Some(tick(&v["before"])?)) {
                    keys.push(k)
                }
                if let Some(limit) = v["limit"].as_u64() {
                    while e.values.len() > limit as usize {
                        keys.push(e.remove_first(None).ok_or("Expiry index inconsistent")?)
                    }
                }
                Ok(json!({"Keys":keys,"Count":e.values.len()}))
            }
            "lru_reset" => {
                let c = context(v)?;
                if !self.lru.contains_key(c) && self.lru.len() >= 64 {
                    return Err("Too many LRU contexts".into());
                }
                self.lru.insert(c.into(), Lru::default());
                Ok(json!({"Reset":true}))
            }
            "lru_touch" => {
                let e = self.lru.get_mut(context(v)?).ok_or("LRU context missing")?;
                let limit = v["limit"]
                    .as_u64()
                    .filter(|x| *x > 0 && *x <= 10000)
                    .ok_or("Invalid LRU bound")? as usize;
                let keys = e.touch(v["key"].as_str().ok_or("Missing key")?.into(), limit)?;
                Ok(json!({"Evicted":keys,"Count":e.values.len()}))
            }
            "inventory" => {
                let context = format!(
                    "{}|{}|{}",
                    v["path"].as_str().ok_or("Missing path")?,
                    v["recurse"].as_bool().unwrap_or(false),
                    v["extension"].as_str().unwrap_or("*")
                );
                if !self.inventories.contains_key(&context) && self.inventories.len() >= 128 {
                    return Err("Too many inventory contexts".into());
                }
                self.inventories.entry(context).or_default().reconcile(v)
            }
            "queue_state" => {
                let root = v["root"].as_str().ok_or("Missing root")?;
                if !self.queues.contains_key(root) && self.queues.len() >= 64 {
                    return Err("Too many queue contexts".into());
                }
                self.queues
                    .entry(root.into())
                    .or_default()
                    .state(std::path::Path::new(root))
            }
            "scheduler" => {
                let root = v["path"].as_str().ok_or("Missing root")?;
                if !self.schedulers.contains_key(root) && self.schedulers.len() >= 64 {
                    return Err("Too many scheduler contexts".into());
                }
                self.schedulers.entry(root.into()).or_default().choose(v)
            }
            "journal_open" => {
                let path = v["path"].as_str().ok_or("Missing journal path")?;
                if !self.journals.contains_key(path) && self.journals.len() >= 64 {
                    return Err("Too many journal contexts".into());
                }
                let store = crate::journal::Journal::open(v)?;
                let result = json!({"Rows":store.rows()});
                self.journals.insert(path.into(), store);
                Ok(result)
            }
            "journal_put" => {
                let path = v["path"].as_str().ok_or("Missing journal path")?;
                self.journals
                    .get_mut(path)
                    .ok_or("Journal not opened")?
                    .put(v)
            }
            _ => Err(format!("Unknown operation: {op}")),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expiry_resists_stale_updates_and_evicts_oldest() {
        let mut e = Expiry::default();
        e.set("a".into(), 1).unwrap();
        e.set("a".into(), 20).unwrap();
        e.set("b".into(), 2).unwrap();
        assert_eq!(e.remove_first(Some(3)), Some("b".into()));
        assert_eq!(e.remove_first(Some(3)), None);
        assert_eq!(e.remove_first(None), Some("a".into()))
    }
    #[test]
    fn lru_keeps_hot_keys_and_bounds_stale_nodes() {
        let mut l = Lru::default();
        l.touch("a".into(), 2).unwrap();
        l.touch("b".into(), 2).unwrap();
        for _ in 0..1000 {
            l.touch("a".into(), 2).unwrap();
        }
        assert_eq!(l.touch("c".into(), 2).unwrap(), vec!["b"]);
        assert!(l.order.len() < 73);
        assert_eq!(l.values.len(), 2)
    }
}

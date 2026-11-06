use crate::{journal::Journal, queue::Catalog, scheduler::Scheduler, storage, structures::Engine};
use serde_json::{json, Value};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "sentinel-native-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, value: &Value) -> PathBuf {
        let path = self
            .0
            .join(name.replace('/', std::path::MAIN_SEPARATOR_STR));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        storage::atomic(&path, value).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.0.parent() == Some(std::env::temp_dir().as_path())
            && self
                .0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sentinel-native-")
        {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
const NOW: &str = "2026-11-06T00:00:00Z";
fn unit() -> Value {
    json!({"Schema":1,"NextIndex":0,"Reset":false,"QueuedAt":NOW,"Events":[{"Id":1,"RecordId":1,"TimeCreated":NOW,"Xml":"<Event/>"},{"Id":22,"RecordId":2,"TimeCreated":NOW,"Xml":"<Event/>"}]})
}
#[test]
fn queue_reconciles_progress_changes_deletion_and_restart() {
    let f = Fixture::new();
    let name = "00000000000000000001-AAAAAAAAAAAAAAAAAAAAAAAA.json";
    let path = f.write(&format!("state/sysmon-analysis/pending/{name}"), &unit());
    let mut c = Catalog::default();
    let first = c.state(&f.0).unwrap();
    assert_eq!(first["PendingEvents"], 2);
    assert_eq!(first["ParsedUnits"], 1);
    assert_eq!(c.state(&f.0).unwrap()["ParsedUnits"], 0);
    let sha = storage::digest(&path).unwrap().0;
    let progress = f.write(
        &format!("state/sysmon-analysis/pending/{name}.progress"),
        &json!({"Schema":1,"UnitName":name,"PayloadSHA256":sha,"EventCount":2,"NextIndex":1}),
    );
    let second = c.state(&f.0).unwrap();
    assert_eq!(second["PendingEvents"], 1);
    assert_eq!(second["ParsedUnits"], 0);
    assert_eq!(
        Catalog::default().state(&f.0).unwrap()["Bytes"],
        second["Bytes"]
    );
    std::fs::remove_file(progress).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(c.state(&f.0).unwrap()["Bytes"], 0);
}
#[test]
fn queue_does_not_trust_cached_payload_or_orphan_progress() {
    let f = Fixture::new();
    let name = "00000000000000000001-AAAAAAAAAAAAAAAAAAAAAAAA.json";
    let path = f.write(&format!("state/sysmon-analysis/pending/{name}"), &unit());
    let mut c = Catalog::default();
    c.state(&f.0).unwrap();
    let sha = storage::digest(&path).unwrap().0;
    f.write(
        &format!("state/sysmon-analysis/pending/{name}.progress"),
        &json!({"Schema":1,"UnitName":name,"PayloadSHA256":sha,"EventCount":2,"NextIndex":1}),
    );
    let mut changed = unit();
    changed["Events"][0]["RecordId"] = 9.into();
    storage::atomic(&path, &changed).unwrap();
    assert!(c.state(&f.0).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(c.state(&f.0).is_err());
}
#[test]
fn scheduler_delays_promotes_retries_and_handles_clock_rollback() {
    let f = Fixture::new();
    let high = f.write(
        "high/a.json",
        &json!({"QueuedAt":"2026-11-05T23:00:00Z","AvailableAfter":"2026-11-06T00:00:10Z"}),
    );
    let normal = f.write("normal/b.json", &json!({"QueuedAt":"2026-11-05T23:00:00Z"}));
    let mut s = Scheduler::default();
    let mut v = json!({"path":f.0,"now":NOW,"high_burst":0,"burst_limit":3,"aging_seconds":30});
    assert_eq!(s.choose(&v).unwrap()["Path"], normal.to_str().unwrap());
    v["now"] = "2026-11-06T00:00:11Z".into();
    assert_eq!(s.choose(&v).unwrap()["Path"], high.to_str().unwrap());
    v["high_burst"] = 3.into();
    assert_eq!(s.choose(&v).unwrap()["Path"], normal.to_str().unwrap());
    v["now"] = NOW.into();
    v["high_burst"] = 0.into();
    assert_eq!(s.choose(&v).unwrap()["Path"], normal.to_str().unwrap());
    storage::atomic(&high, &json!({"QueuedAt":NOW})).unwrap();
    assert_eq!(s.choose(&v).unwrap()["Path"], high.to_str().unwrap());
    std::fs::remove_file(high).unwrap();
    std::fs::remove_file(normal).unwrap();
    assert!(s.choose(&v).unwrap()["Path"].is_null());
}
#[test]
fn journal_compaction_recovers_empty_replacement_and_legacy_snapshot() {
    let f = Fixture::new();
    let path = f.write(
        "dedupe.json",
        &json!([{"Key":"legacy","LastQueued":NOW,"Score":1}]),
    );
    let args = json!({"path":path,"mode":"path","now":NOW,"max_age":3600});
    let mut s = Journal::open(&args).unwrap();
    f.write("dedupe.json.wal.empty", &Value::Null);
    std::fs::write(f.0.join("dedupe.json.wal.empty"), b"").unwrap();
    let mut put = args.clone();
    put["key"] = "new".into();
    put["at"] = NOW.into();
    put["score"] = 45.into();
    for _ in 0..128 {
        s.put(&put).unwrap();
    }
    assert_eq!(
        std::fs::metadata(f.0.join("dedupe.json.wal"))
            .unwrap()
            .len(),
        0
    );
    let recovered = Journal::open(&args).unwrap().rows();
    assert_eq!(recovered.as_array().unwrap().len(), 2);
    // A crash after the snapshot was committed but before WAL truncation is idempotent.
    s.put(&put).unwrap();
    let wal = std::fs::read(f.0.join("dedupe.json.wal")).unwrap();
    storage::atomic(&path, &s.rows()).unwrap();
    assert_eq!(
        Journal::open(&args)
            .unwrap()
            .rows()
            .as_array()
            .unwrap()
            .len(),
        2
    );
    std::fs::write(f.0.join("dedupe.json.wal"), &wal[..wal.len() - 1]).unwrap();
    assert!(Journal::open(&args).is_err());
}
#[test]
fn journal_rejects_checksum_mutation_and_foreign_writer() {
    let f = Fixture::new();
    let path = f.0.join("dedupe.json");
    let args = json!({"path":path,"mode":"hash","now":NOW,"max_age":3600});
    let mut a = Journal::open(&args).unwrap();
    let mut b = Journal::open(&args).unwrap();
    let mut put = args.clone();
    put["key"] = "ABC".into();
    put["at"] = NOW.into();
    a.put(&put).unwrap();
    assert!(b.put(&put).is_err());
    let wal = f.0.join("dedupe.json.wal");
    let data = std::fs::read_to_string(&wal).unwrap().replace("abc", "abd");
    std::fs::write(&wal, data).unwrap();
    assert!(Journal::open(&args).is_err());
}
#[test]
fn inventory_reconciles_growth_deletion_and_restart() {
    let f = Fixture::new();
    let mut a = storage::Inventory::default();
    let v = json!({"path":f.0,"recurse":true,"extension":"json"});
    let one = f.write("a/a.json", &json!({"x":1}));
    let first = a.reconcile(&v).unwrap();
    assert_eq!(first["Files"], 1);
    assert_eq!(a.reconcile(&v).unwrap()["ChangedFiles"], 0);
    storage::atomic(&one, &json!({"x":"longer"})).unwrap();
    let second = a.reconcile(&v).unwrap();
    assert!(second["Bytes"].as_u64().unwrap() > first["Bytes"].as_u64().unwrap());
    assert_eq!(
        storage::Inventory::default().reconcile(&v).unwrap()["Bytes"],
        second["Bytes"]
    );
    std::fs::remove_file(one).unwrap();
    assert_eq!(a.reconcile(&v).unwrap()["Files"], 0);
}
#[test]
fn expiry_updates_are_case_insensitive_and_heap_remains_bounded() {
    let mut e = Engine::default();
    e.execute("expiry_reset", &json!({"context":"x","rows":[]}))
        .unwrap();
    for _ in 0..1000 {
        e.execute("expiry_set", &json!({"context":"x","key":"ABC","at":"10"}))
            .unwrap();
    }
    e.execute("expiry_set", &json!({"context":"x","key":"abc","at":"20"}))
        .unwrap();
    assert_eq!(
        e.execute("expiry_take", &json!({"context":"x","before":"15"}))
            .unwrap()["Count"],
        1
    );
    assert_eq!(
        e.execute("expiry_take", &json!({"context":"x","before":"21"}))
            .unwrap()["Keys"],
        json!(["abc"])
    );
}
#[test]
fn abi_requests_refuse_duplicate_keys_and_unknown_operations() {
    for input in [
        br#"{"op":"hash","Op":"scan"}"#.as_slice(),
        br#"{"op":"unknown"}"#.as_slice(),
        b"not-json".as_slice(),
    ] {
        let v: Value = serde_json::from_slice(&crate::request(input)).unwrap();
        assert_eq!(v["Ok"], false);
    }
}

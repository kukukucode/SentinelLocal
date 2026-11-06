mod canonical;
mod journal;
mod queue;
mod scan;
mod scheduler;
mod storage;
mod structures;
#[cfg(test)]
mod tests;

use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

static ENGINE: OnceLock<Mutex<structures::Engine>> = OnceLock::new();

pub fn request(input: &[u8]) -> Vec<u8> {
    let answer = std::panic::catch_unwind(|| -> Result<Value, String> {
        if input.len() > 16 * 1024 * 1024 {
            return Err("Request exceeds 16 MiB".into());
        }
        let value: Value = canonical::parse(input)?;
        match value["op"].as_str().ok_or("Missing operation")? {
            "scan" => scan::scan(&value),
            "hash" => scan::hash(&value),
            op => ENGINE
                .get_or_init(|| Mutex::new(structures::Engine::default()))
                .lock()
                .map_err(|_| "Engine state unavailable")?
                .execute(op, &value),
        }
    });
    let output = match answer {
        Ok(Ok(data)) => json!({"Ok":true,"Data":data}),
        Ok(Err(error)) => json!({"Ok":false,"Error":error}),
        Err(_) => {
            json!({"Ok":false,"Error":"Native operation panicked; no success is established"})
        }
    };
    struct Bounded(Vec<u8>);
    impl std::io::Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + bytes.len() > 16 * 1024 * 1024 {
                return Err(std::io::Error::other("Reply exceeds 16 MiB"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut buffer = Bounded(Vec::new());
    if serde_json::to_writer(&mut buffer, &output).is_err() {
        return br#"{"Ok":false,"Error":"Reply exceeds serialization bound"}"#.to_vec();
    }
    buffer.0
}

/// The host owns input memory; the returned allocation must be freed with sentinel_free.
/// No Rust reference is retained across the ABI boundary.
#[no_mangle]
pub unsafe extern "C" fn sentinel_call(
    input: *const u8,
    length: usize,
    output_length: *mut usize,
) -> *mut u8 {
    if input.is_null() || output_length.is_null() || length > 16 * 1024 * 1024 {
        return std::ptr::null_mut();
    }
    let bytes = request(std::slice::from_raw_parts(input, length)).into_boxed_slice();
    *output_length = bytes.len();
    Box::into_raw(bytes) as *mut u8
}

#[no_mangle]
pub unsafe extern "C" fn sentinel_free(pointer: *mut u8, length: usize) {
    if !pointer.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            pointer, length,
        )));
    }
}

use std::io::{Read, Write};
fn main() {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut input)
    {
        eprintln!("{e}");
        std::process::exit(2);
    }
    let output = sentinel_engine::request(&input);
    let ok = serde_json::from_slice::<serde_json::Value>(&output)
        .ok()
        .and_then(|v| v["Ok"].as_bool())
        == Some(true);
    if std::io::stdout().write_all(&output).is_err() {
        std::process::exit(2);
    }
    if !ok {
        std::process::exit(2);
    }
}

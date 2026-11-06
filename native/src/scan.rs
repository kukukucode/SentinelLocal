use crate::{canonical::{self,field,text},storage};
use serde_json::{json,Value};
use sha2::{Digest,Sha256};
use std::{collections::HashSet,io::{BufRead,BufReader},path::Path};

pub fn hash(v:&Value)->Result<Value,String>{let(d,n)=storage::digest(Path::new(v["path"].as_str().ok_or("Missing path")?))?;Ok(json!({"SHA256":d,"ByteLength":n}))}
fn capture(row:&Value,kind:&str,c:&Value)->Result<bool,String>{
    if c.is_null(){return Ok(false)}
    let from=canonical::ticks(c["start"].as_str().ok_or("Missing capture start")?)?;let to=canonical::ticks(c["end"].as_str().ok_or("Missing capture end")?)?;
    let relevant=match kind{
        "process-events"=>text(row,"Type")==Some("ProcessCreated")&&text(row,"Source")==Some("Sysmon")&&field(row,"MetadataComplete").and_then(Value::as_bool)==Some(true),
        "sysmon-events"=>field(row,"EventId").and_then(Value::as_u64)==Some(255),
        "alerts"=>text(row,"Type")==Some("EventLogCursorReset")&&text(row,"Log")==Some("Sysmon"),
        "errors"=>matches!(text(row,"Component"),Some("Sysmon"|"SysmonAnalysis")),_=>false};
    if !relevant{return Ok(false)}
    let time=canonical::ticks(text(row,if kind=="sysmon-events"{"EventTime"}else{"Timestamp"}).ok_or("Relevant record has no timestamp")?)?;
    if time<from||time>to{return Ok(false)}
    if kind=="process-events"{let pid=field(row,"Process").and_then(|p|field(p,"ProcessId")).and_then(Value::as_u64).ok_or("Invalid process identity")?;return Ok(c["pids"].as_array().ok_or("Missing trial PIDs")?.iter().any(|x|x.as_u64()==Some(pid)))}
    Ok(true)
}
pub fn scan(v:&Value)->Result<Value,String>{
    let path=Path::new(v["path"].as_str().ok_or("Missing path")?);let mut reader=BufReader::with_capacity(65536,storage::read(path)?);
    let name=path.file_name().and_then(|s|s.to_str()).ok_or("Invalid filename")?;let kind=name.split('.').next().unwrap_or("");
    let mut hash=Sha256::new();let mut bytes=0u64;let mut lines=0u64;let mut first=Value::Null;let mut last=Value::Null;let mut rows=Vec::new();let mut compatibility=Vec::new();let mut result_bytes=0usize;
    let mut min_time:Option<i128>=None;let mut max_time:Option<i128>=None;let mut buffer=Vec::new();
    loop{
        buffer.clear();let n=reader.by_ref().take(16*1024*1024+1).read_until(b'\n',&mut buffer).map_err(|e|e.to_string())?;
        if n==0{break}if buffer.len()>16*1024*1024{return Err("Log record exceeds 16 MiB".into())}
        hash.update(&buffer);bytes+=n as u64;
        let line=buffer.strip_suffix(b"\n").unwrap_or(&buffer);let line=line.strip_suffix(b"\r").unwrap_or(line);
        let row=canonical::parse(line)?;let prev=text(&row,"_ChainPrev").ok_or("Missing previous hash")?;let recorded=text(&row,"_ChainHash").ok_or("Missing record hash")?;
        if text(&row,"_ChainAlg")!=Some("SHA256")||recorded.len()!=64||!recorded.bytes().all(|x|x.is_ascii_hexdigit()){return Err("Invalid chain fields".into())}
        if lines==0{first=prev.into()}else if last.as_str().map(|x|!x.eq_ignore_ascii_case(prev)).unwrap_or(true){return Err(format!("Previous hash mismatch at line {}",lines+1))}
        let mut payload=serde_json::Map::new();let skip:HashSet<_>=["_chainalg","_chainprev","_chainhash"].into_iter().collect();
        for(k,x)in row.as_object().ok_or("Record is not an object")?{if !skip.contains(k.to_ascii_lowercase().as_str()){payload.insert(k.clone(),x.clone());}}
        match canonical::powershell(&Value::Object(payload)){
            Ok(canonical)=>{let mut h=Sha256::new();h.update(prev.as_bytes());h.update(b"\n");h.update(canonical.as_bytes());if !storage::hex(h.finalize()).eq_ignore_ascii_case(recorded){return Err(format!("Hash mismatch at line {}",lines+1))}},
            Err(_)=>{result_bytes+=line.len();if compatibility.len()>=1024{return Err("Too many compatibility records; use the legacy verifier".into())}compatibility.push(json!({"LineNumber":lines+1,"Line":std::str::from_utf8(line).map_err(|e|e.to_string())?}));}
        }
        if let Some(t)=text(&row,"Timestamp"){let t=canonical::ticks(t)?;min_time=Some(min_time.map_or(t,|x|x.min(t)));max_time=Some(max_time.map_or(t,|x|x.max(t)));}
        if capture(&row,kind,&v["capture"])?{result_bytes+=line.len();rows.push(row.clone());}
        if result_bytes>8*1024*1024{return Err("Captured/compatibility data exceeds 8 MiB; no result was truncated".into())}
        last=recorded.into();lines+=1;
    }
    Ok(json!({"LineCount":lines,"ByteLength":bytes,"LastHash":last,"FirstPreviousHash":first,"SHA256":storage::hex(hash.finalize()),"Rows":rows,"CompatibilityRows":compatibility,"CanonicalValidationComplete":compatibility.is_empty(),"MinTimestampTicks":min_time.map(|x|x.to_string()),"MaxTimestampTicks":max_time.map(|x|x.to_string())}))
}
use std::io::Read;

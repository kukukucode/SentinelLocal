use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::collections::HashSet;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str("JSON without duplicate properties") }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Strict,E> { Ok(Strict(Value::Bool(v))) }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Strict,E> { Ok(Strict(v.into())) }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Strict,E> { Ok(Strict(v.into())) }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict,E> { Number::from_f64(v).map(|n| Strict(Value::Number(n))).ok_or_else(|| E::custom("Non-finite number")) }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Strict,E> { Ok(Strict(v.into())) }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Strict,E> { Ok(Strict(v.into())) }
            fn visit_unit<E: de::Error>(self) -> Result<Strict,E> { Ok(Strict(Value::Null)) }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Strict,A::Error> { let mut v=Vec::new(); while let Some(x)=a.next_element::<Strict>()? {v.push(x.0)} Ok(Strict(Value::Array(v))) }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Strict,A::Error> {
                let mut m=Map::new(); let mut seen=HashSet::new();
                while let Some(key)=a.next_key::<String>()? {
                    if !seen.insert(key.to_lowercase()) {return Err(de::Error::custom("Duplicate/case-colliding JSON property"))}
                    m.insert(key,a.next_value::<Strict>()?.0);
                }
                Ok(Strict(Value::Object(m)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn parse(bytes: &[u8]) -> Result<Value,String> {
    let bytes=bytes.strip_prefix(&[0xef,0xbb,0xbf]).unwrap_or(bytes);
    let mut d=serde_json::Deserializer::from_slice(bytes);
    let result=Strict::deserialize(&mut d).map_err(|e| e.to_string())?.0;
    d.end().map_err(|e|e.to_string())?;
    Ok(result)
}
pub fn field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> { value.as_object()?.iter().find(|(k,_)|k.eq_ignore_ascii_case(key)).map(|(_,v)|v) }
pub fn text<'a>(value: &'a Value,key: &str)->Option<&'a str>{field(value,key)?.as_str()}
pub fn ticks(value: &str)->Result<i128,String>{let d=chrono::DateTime::parse_from_rfc3339(value).map_err(|_|"Timestamp requires an explicit RFC3339 offset")?;Ok(d.timestamp() as i128*10_000_000+d.timestamp_subsec_nanos() as i128/100)}
fn string(s:&str)->String {
    serde_json::to_string(s).expect("String serialization cannot fail")
        .replace('\'',"\\u0027").replace('<',"\\u003c").replace('>',"\\u003e").replace('&',"\\u0026")
        .replace('\u{85}',"\\u0085").replace('\u{2028}',"\\u2028").replace('\u{2029}',"\\u2029")
}
pub fn powershell(value:&Value)->Result<String,String>{fn write(v:&Value,out:&mut String,depth:usize)->Result<(),String>{
    if depth>12{return Err("Depth requires PowerShell compatibility validation".into())}
    match v {
        Value::Null=>out.push_str("null"),Value::Bool(b)=>out.push_str(if *b{"true"}else{"false"}),
        Value::String(s)=>out.push_str(&string(s)),
        Value::Number(n)=>{if !n.is_i64()&&!n.is_u64(){return Err("Numeric representation requires PowerShell compatibility validation".into())}out.push_str(&n.to_string())},
        Value::Array(a)=>{out.push('[');for(i,x)in a.iter().enumerate(){if i>0{out.push(',')}write(x,out,depth+1)?}out.push(']')},
        Value::Object(m)=>{out.push('{');for(i,(k,x))in m.iter().enumerate(){if !k.is_ascii(){return Err("Property name requires PowerShell compatibility validation".into())}if i>0{out.push(',')}out.push_str(&string(k));out.push(':');write(x,out,depth+1)?}out.push('}')},
    }Ok(())}
    let mut result=String::new();write(value,&mut result,0)?;Ok(result)
}

#[cfg(test)]mod tests{use super::*;
#[test]fn html_and_unicode_match_ps51(){assert_eq!(powershell(&parse(br#"{"s":"a'b<c>d&e/\u0085\u2028\u2029"}"#).unwrap()).unwrap(),r#"{"s":"a\u0027b\u003cc\u003ed\u0026e/\u0085\u2028\u2029"}"#)}
#[test]fn never_guess_numeric_or_duplicates(){assert!(powershell(&parse(br#"{"n":0.1}"#).unwrap()).is_err());assert!(parse(br#"{"A":1,"a":2}"#).is_err());assert!(parse(br#"{"n":1} trailing"#).is_err())}
#[test]fn hundred_nanosecond_precision(){assert_eq!(ticks("2026-11-06T00:00:00.0000001Z").unwrap()-ticks("2026-11-06T09:00:00+09:00").unwrap(),1)}
}

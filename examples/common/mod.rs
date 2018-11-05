pub mod event_loop;
pub mod types;

use serde::de::DeserializeOwned;
use serde_json;
use std::fs::File;
use std::io::Read;

pub fn read_config<T: DeserializeOwned>(path: &str) -> T {
    let mut file = unwrap!(File::open(path));
    let mut content = String::new();
    unwrap!(file.read_to_string(&mut content));
    unwrap!(serde_json::from_str(&content))
}

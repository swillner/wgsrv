use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::io::{BufReader, BufWriter};
use wireguard_control::Key;

fn key_from_base64str<'de, D>(deserializer: D) -> Result<Key, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    Key::from_base64(&s).map_err(serde::de::Error::custom)
}

fn key_to_base64str<S>(key: &Key, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    key.to_base64().serialize(serializer)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConf {
    pub domain: String,
    pub net4: Ipv4Network,
    pub net6: Ipv6Network,
    pub port: u16,
    #[serde(
        deserialize_with = "key_from_base64str",
        serialize_with = "key_to_base64str"
    )]
    pub private_key: Key,
    pub peers: HashMap<String, PeerConf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerConf {
    #[serde(
        deserialize_with = "key_from_base64str",
        serialize_with = "key_to_base64str"
    )]
    pub public_key: Key,
    pub id: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Settings {
    #[serde(skip)]
    filename: String,
    pub networks: HashMap<String, NetworkConf>,
}

impl Settings {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn Error>> {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        let mut settings: Self = serde_json::from_reader(reader)?;
        settings.filename = path.to_string();
        Ok(settings)
    }

    pub fn persist(&self) -> Result<(), Box<dyn Error>> {
        if self.filename.is_empty() {
            return Err("No filename set".into());
        }
        let file = std::fs::File::create(&self.filename)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, self)?;
        Ok(())
    }
}

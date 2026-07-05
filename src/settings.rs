use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
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
        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                return Ok(Self {
                    filename: path.to_string(),
                    networks: HashMap::new(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        let reader = BufReader::new(file);
        let mut settings: Self = serde_json::from_reader(reader)?;
        settings.filename = path.to_string();
        Ok(settings)
    }

    pub fn persist(&self) -> Result<(), Box<dyn Error>> {
        if self.filename.is_empty() {
            return Err("No filename set".into());
        }

        let target = Path::new(&self.filename);
        let temp = temp_path_for(target)?;
        let result = persist_atomic(self, &temp, target);
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

fn temp_path_for(target: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let filename = target.file_name().ok_or("Invalid filename")?;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();

    Ok(parent.join(format!(
        ".{}.tmp.{}.{}",
        filename.to_string_lossy(),
        std::process::id(),
        timestamp
    )))
}

fn persist_atomic(settings: &Settings, temp: &Path, target: &Path) -> Result<(), Box<dyn Error>> {
    {
        let file = OpenOptions::new().write(true).create_new(true).open(temp)?;
        let writer = BufWriter::new(file);
        write_settings(writer, settings)?;
    }

    fs::rename(temp, target)?;
    sync_parent_dir(target)?;
    Ok(())
}

fn write_settings(
    mut writer: BufWriter<fs::File>,
    settings: &Settings,
) -> Result<(), Box<dyn Error>> {
    serde_json::to_writer_pretty(&mut writer, settings)?;
    writer.flush()?;
    writer.into_inner()?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(target: &Path) -> Result<(), Box<dyn Error>> {
    let parent = target
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_dir(_target: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir(name: &str) -> PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wgsrv-{}-{}-{}",
            name,
            std::process::id(),
            timestamp
        ))
    }

    #[test]
    fn persist_rejects_missing_filename() {
        let settings = Settings {
            filename: String::new(),
            networks: HashMap::new(),
        };

        assert!(settings.persist().is_err());
    }

    #[test]
    fn persist_writes_settings_file() {
        let dir = test_dir("persist");
        fs::create_dir(&dir).unwrap();
        let filename = dir.join("settings.json");
        let settings = Settings {
            filename: filename.to_string_lossy().to_string(),
            networks: HashMap::new(),
        };

        settings.persist().unwrap();

        let persisted = fs::read_to_string(&filename).unwrap();
        assert!(persisted.contains("\"networks\""));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_persist_leaves_existing_file_unchanged() {
        let dir = test_dir("failed-persist");
        fs::create_dir(&dir).unwrap();
        let filename = dir.join("settings.json");
        fs::write(&filename, "original").unwrap();
        let settings = Settings {
            filename: filename.to_string_lossy().to_string(),
            networks: HashMap::new(),
        };
        let temp = dir.join("settings.tmp");

        let result = persist_atomic(&settings, &temp, &dir);

        assert!(result.is_err());
        assert_eq!(fs::read_to_string(&filename).unwrap(), "original");
        let _ = fs::remove_file(temp);
        fs::remove_dir_all(dir).unwrap();
    }
}

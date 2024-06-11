use crate::helpers::{get_nth_ip, user_confirm};
use crate::settings::{PeerConf, Settings};
use clap::Subcommand;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use std::error::Error;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpListener};
use wireguard_control::{Backend, DeviceUpdate, Key, PeerConfigBuilder};

#[derive(Subcommand)]
pub enum Command {
    Delete {
        #[arg()]
        network: String,

        #[arg()]
        peer: String,
    },
    List {
        #[arg()]
        network: String,
    },
    Register {
        #[arg()]
        network: String,

        #[arg(long, default_value = "0.0.0.0:52001")]
        listen: SocketAddr,
    },
    Show {
        #[arg()]
        network: String,

        #[arg()]
        peer: String,
    },
}

impl Command {
    pub fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        match self {
            Command::Delete { network, peer } => delete(settings, network, peer),
            Command::List { network } => list(&settings, network),
            Command::Register { network, listen } => register(settings, network, listen),
            Command::Show { network, peer } => show(&settings, network, peer),
        }
    }
}

fn delete(
    mut settings: Settings,
    network_name: String,
    peer_name: String,
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or("Unknown network")?;
    let peer = network.peers.remove(&peer_name).ok_or("Unknown peer")?;
    if user_confirm(&format!(
        "Delete peer {} with public key {}?",
        peer_name,
        peer.public_key.to_base64()
    )) {
        let wg_interface = network_name.parse()?;
        DeviceUpdate::new()
            .remove_peer_by_key(&peer.public_key)
            .apply(&wg_interface, Backend::Kernel)?;
        settings.persist()?;
    }
    Ok(())
}

fn list(settings: &Settings, network: String) -> Result<(), Box<dyn Error>> {
    let network = settings.networks.get(&network).ok_or("Unknown network")?;
    println!("Peers in {}:", network.domain);
    for (name, peer) in network.peers.iter().sorted_by_key(|(_, p)| p.id) {
        println!(
            "  {}: {}",
            name,
            get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?.ip()
        );
    }
    Ok(())
}

fn register(
    mut settings: Settings,
    network_name: String,
    listen: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get_mut(&network_name)
        .ok_or("Unknown network")?;
    let listener = TcpListener::bind(listen)?;
    println!("Waiting for peer to connect...");
    match listener.accept() {
        Ok((socket, _addr)) => {
            println!("Peer connected");
            let mut reader = BufReader::new(socket.try_clone()?);

            let peer_name = {
                let mut peer_name = String::new();
                reader.read_line(&mut peer_name)?;
                peer_name.pop(); // remove newline
                if peer_name.len() < 3 {
                    return Err("Invalid peer name".into());
                }
                if network.peers.contains_key(&peer_name) {
                    return Err("Peer already registered".into());
                }
                peer_name
            };

            let peer_public_key = {
                let mut peer_public_key = String::new();
                reader.read_line(&mut peer_public_key)?;
                peer_public_key.pop(); // remove newline
                Key::from_base64(&peer_public_key)?
            };

            let used_peer_ids: Vec<u32> = network.peers.values().map(|p| p.id).collect();
            let peer_id = (2..)
                .find(|id| !used_peer_ids.contains(id))
                .ok_or("No more valid slots in network")?;
            let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer_id)?;
            let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer_id)?;

            if !user_confirm(&format!(
                "Register peer {} with public key {} with ips {} and {}?",
                peer_name,
                peer_public_key.to_base64(),
                ip4.ip(),
                ip6.ip(),
            )) {
                return Err("User cancelled".into());
            }

            let public_key = network.private_key.generate_public();
            write!(
                BufWriter::new(socket.try_clone()?),
                "[Interface]
Address = {},{}
MTU = 1280 # otherwise ssh over wireguard hangs
PrivateKey = PRIVATE_KEY

[Peer]
PublicKey = {}
AllowedIPs = {},{}
Endpoint = HOST_IP:{}
",
                ip4,
                ip6,
                public_key.to_base64(),
                network.net4,
                network.net6,
                network.port
            )?;

            let wg_interface = network_name.parse()?;
            let peer = PeerConfigBuilder::new(&peer_public_key)
                .replace_allowed_ips()
                .add_allowed_ip(ip4.ip(), 32)
                .add_allowed_ip(ip6.ip(), 128);
            DeviceUpdate::new()
                .add_peer(peer)
                .apply(&wg_interface, Backend::Kernel)?;

            network.peers.insert(
                peer_name,
                PeerConf {
                    public_key: peer_public_key,
                    id: peer_id,
                },
            );

            settings.persist()
        }
        Err(e) => Err(e.into()),
    }
}

fn show(
    settings: &Settings,
    network_name: String,
    peer_name: String,
) -> Result<(), Box<dyn Error>> {
    let network = settings
        .networks
        .get(&network_name)
        .ok_or("Unknown network")?;
    let peer = network.peers.get(&peer_name).ok_or("Unknown peer")?;
    let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?;
    let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?;
    println!(
        "Peer {} in {}:
  Public key: {}
  IPv4: {}
  IPv6: {}",
        peer_name,
        network.domain,
        peer.public_key.to_base64(),
        ip4.ip(),
        ip6.ip()
    );
    Ok(())
}
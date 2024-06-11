use crate::helpers::{get_nth_ip, user_confirm};
use crate::settings::{NetworkConf, Settings};
use clap::Subcommand;
use futures::{future, stream::TryStreamExt};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use itertools::Itertools;
use log::info;
use netlink_packet_route::route::RouteAttribute;
use rtnetlink::IpVersion;
use std::collections::HashMap;
use std::error::Error;
use std::future::Future;
use std::net::IpAddr;
use wireguard_control::{Backend, DeviceUpdate, KeyPair, PeerConfigBuilder};

#[derive(Subcommand)]
pub enum Command {
    Add {
        #[arg()]
        name: String,

        #[arg(long)]
        net4: Ipv4Network,

        #[arg(long)]
        net6: Ipv6Network,

        #[arg()]
        port: u16,
    },
    Delete {
        #[arg()]
        name: String,
    },
    Down {
        #[arg()]
        name: Option<String>,
    },
    List,
    Show {
        #[arg()]
        name: String,
    },
    Up {
        #[arg()]
        name: Option<String>,
    },
}

impl Command {
    pub fn run(self, settings: Settings) -> Result<(), Box<dyn Error>> {
        match self {
            Command::Add {
                name,
                net4,
                net6,
                port,
            } => add(settings, name, net4, net6, port),
            Command::Delete { name } => delete(settings, &name),
            Command::Down { name } => with_netlink_handle(|handle| async move {
                if let Some(name) = name {
                    settings.networks.get(&name).ok_or("Unknown network")?;
                    down(&name, &handle).await
                } else {
                    for (name, _) in &settings.networks {
                        down(&name, &handle).await?;
                    }
                    Ok(())
                }
            }),
            Command::List => list(&settings),
            Command::Show { name } => show(&settings, name),
            Command::Up { name } => with_netlink_handle(|handle| async move {
                if let Some(name) = name {
                    up(
                        &name,
                        settings.networks.get(&name).ok_or("Unknown network")?,
                        &handle,
                    )
                    .await
                } else {
                    for (name, network) in &settings.networks {
                        up(&name, network, &handle).await?;
                    }
                    Ok(())
                }
            }),
        }
    }
}

fn add(
    mut settings: Settings,
    name: String,
    net4: Ipv4Network,
    net6: Ipv6Network,
    port: u16,
) -> Result<(), Box<dyn Error>> {
    let network = settings.networks.get(&name);
    if network.is_some() {
        return Err("Network already exists".into());
    }
    let network = NetworkConf {
        domain: name.clone(),
        net4,
        net6,
        port,
        private_key: KeyPair::generate().private,
        peers: HashMap::new(),
    };
    with_netlink_handle(|handle| async move {
        up(&name, &network, &handle).await?;
        settings.networks.insert(name, network);
        settings.persist()?;
        Ok(())
    })
}

fn delete(mut settings: Settings, name: &String) -> Result<(), Box<dyn Error>> {
    settings.networks.get(name).ok_or("Unknown network")?;
    if user_confirm(&format!("Delete network {}?", name)) {
        with_netlink_handle(|handle| async move {
            let iface = Interface::new(name, &handle).await?;
            iface.delete().await?;
            settings.networks.remove(name);
            settings.persist()?;
            Ok(())
        })?;
    }
    Ok(())
}

async fn down(name: &String, handle: &rtnetlink::Handle) -> Result<(), Box<dyn Error>> {
    info!("Shutting down network: {}", name);
    let iface = Interface::new(name, handle).await?;
    iface.down().await
}

fn list(settings: &Settings) -> Result<(), Box<dyn Error>> {
    println!("Networks:");
    for (name, network) in &settings.networks {
        println!(
            "  {}: {} ({} peers)",
            name,
            network.net4,
            network.peers.len()
        );
    }
    Ok(())
}

fn show(settings: &Settings, name: String) -> Result<(), Box<dyn Error>> {
    let network = settings.networks.get(&name).ok_or("Unknown network")?;
    println!("Network: {}", network.domain);
    println!("  IPv4: {}", network.net4);
    println!("  IPv6: {}", network.net6);
    println!("  Port: {}", network.port);
    println!("  Private key: {}", network.private_key.to_base64());
    println!("  Peers:");
    for (name, peer) in network.peers.iter().sorted_by_key(|(_, p)| p.id) {
        println!(
            "    {}: {}",
            name,
            get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?.ip()
        );
    }
    Ok(())
}

async fn up(
    name: &String,
    network: &NetworkConf,
    handle: &rtnetlink::Handle,
) -> Result<(), Box<dyn Error>> {
    info!("Initializing network: {}", name);
    let wg_interface = name.parse()?;
    let mut update = DeviceUpdate::new()
        .set_private_key(network.private_key.clone())
        .set_public_key(network.private_key.generate_public())
        .set_listen_port(network.port)
        .replace_peers();
    for (peer_name, peer) in &network.peers {
        let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), peer.id)?;
        let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), peer.id)?;
        info!("Adding peer {}: {} {}", peer_name, ip4, ip6);
        let peer = PeerConfigBuilder::new(&peer.public_key)
            .replace_allowed_ips()
            .add_allowed_ip(ip4.ip(), 32)
            .add_allowed_ip(ip6.ip(), 128);
        update = update.add_peer(peer);
    }
    update.apply(&wg_interface, Backend::Kernel)?;
    let ip4 = get_nth_ip(&IpNetwork::V4(network.net4), 1)?;
    let ip6 = get_nth_ip(&IpNetwork::V6(network.net6), 1)?;
    let iface = Interface::new(name, handle).await?;
    iface.up(Some(1280)).await?;
    iface.clear().await?;
    iface.add_address(&ip4).await?;
    iface.add_address(&ip6).await
}

#[tokio::main]
async fn with_netlink_handle<F, Fut, R>(f: F) -> Result<R, Box<dyn Error>>
where
    F: FnOnce(rtnetlink::Handle) -> Fut,
    Fut: Future<Output = Result<R, Box<dyn Error>>>,
{
    let (connection, handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);
    f(handle).await
}

struct Interface<'a> {
    index: u32,
    handle: &'a rtnetlink::Handle,
}

fn map_netlink_error(e: rtnetlink::Error) -> Box<dyn Error> {
    match e {
        rtnetlink::Error::NetlinkError(e) => e.to_io().into(),
        rtnetlink::Error::UnexpectedMessage(_) => "Unexpected netlink message".into(),
        _ => e.into(),
    }
}

impl<'a> Interface<'a> {
    pub async fn new(name: &String, handle: &'a rtnetlink::Handle) -> Result<Self, Box<dyn Error>> {
        let mut links = handle.link().get().match_name(name.clone()).execute();
        if let Some(link) = links.try_next().await.map_err(map_netlink_error)? {
            Ok(Self {
                index: link.header.index,
                handle,
            })
        } else {
            handle
                .link()
                .add()
                .name(name.clone())
                .execute()
                .await
                .map_err(map_netlink_error)?;
            let mut links = handle.link().get().match_name(name.clone()).execute();
            let link = links
                .try_next()
                .await
                .map_err(map_netlink_error)?
                .ok_or("Link not found after creation")?;
            Ok(Self {
                index: link.header.index,
                handle,
            })
        }
    }

    pub async fn down(&self) -> Result<(), Box<dyn Error>> {
        self.handle
            .link()
            .set(self.index)
            .down()
            .execute()
            .await
            .map_err(map_netlink_error)
    }

    pub async fn up(&self, mtu: Option<u32>) -> Result<(), Box<dyn Error>> {
        let mut req = self.handle.link().set(self.index);
        if let Some(mtu) = mtu {
            req = req.mtu(mtu);
        }
        req.up().execute().await.map_err(map_netlink_error)
    }

    pub async fn delete_routes(&self) -> Result<(), Box<dyn Error>> {
        for version in [IpVersion::V4, IpVersion::V6] {
            let routes = self
                .handle
                .route()
                .get(version)
                .execute()
                .try_filter(|route| {
                    future::ready(
                        route.attributes.iter().find_map(|attribute| {
                            if let RouteAttribute::Oif(iface) = attribute {
                                Some(*iface)
                            } else {
                                None
                            }
                        }) == Some(self.index),
                    )
                })
                .try_collect::<Vec<_>>()
                .await
                .map_err(map_netlink_error)?;
            for route in routes {
                self.handle
                    .route()
                    .del(route)
                    .execute()
                    .await
                    .map_err(map_netlink_error)?;
            }
        }
        Ok(())
    }

    pub async fn delete_addresses(&self) -> Result<(), Box<dyn Error>> {
        let addresses = self
            .handle
            .address()
            .get()
            .set_link_index_filter(self.index)
            .execute()
            .try_collect::<Vec<_>>()
            .await
            .map_err(map_netlink_error)?;
        for address in addresses {
            self.handle
                .address()
                .del(address)
                .execute()
                .await
                .map_err(map_netlink_error)?;
        }
        Ok(())
    }

    pub async fn add_address(&self, ipn: &IpNetwork) -> Result<(), Box<dyn Error>> {
        self.handle
            .address()
            .add(self.index, ipn.ip(), ipn.prefix())
            .execute()
            .await
            .map_err(map_netlink_error)
    }

    #[allow(dead_code)]
    pub async fn add_route(&self, ipn: &IpNetwork) -> Result<(), Box<dyn Error>> {
        let req = self.handle.route().add().output_interface(self.index);
        match ipn.network() {
            IpAddr::V4(ip) => req
                .v4()
                .destination_prefix(ip, ipn.prefix())
                .execute()
                .await
                .map_err(map_netlink_error),
            IpAddr::V6(ip) => req
                .v6()
                .destination_prefix(ip, ipn.prefix())
                .execute()
                .await
                .map_err(map_netlink_error),
        }
    }

    pub async fn clear(&self) -> Result<(), Box<dyn Error>> {
        self.delete_routes().await?;
        self.delete_addresses().await
    }

    #[allow(dead_code)]
    pub async fn restart(&self, mtu: Option<u32>) -> Result<(), Box<dyn Error>> {
        self.down().await.ok();
        self.up(mtu).await
    }

    pub async fn delete(&self) -> Result<(), Box<dyn Error>> {
        self.handle
            .link()
            .del(self.index)
            .execute()
            .await
            .map_err(map_netlink_error)
    }
}

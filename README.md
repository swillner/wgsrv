# wgsrv

`wgsrv` is a small helper for running a WireGuard server with a JSON
configuration file. Its main job is to make client registration less annoying:
run one command on the server, run one script on the client, and the client key
exchange and server-side peer registration happen without manually copying
public keys back and forth.

It is intentionally simple. There is no daemon and no database. The server
state lives in `/etc/wireguard/wgsrv.json` unless you pass another path with
`--settings`.

## What It Does

- creates and removes WireGuard networks
- brings configured networks up and down
- stores network and peer state in JSON
- allocates peer addresses from the configured IPv4 and IPv6 networks
- registers a client by accepting its name and public key, then returning a
  client config
- includes a client-side helper script for generating keys and installing the
  returned config

Most commands need root, because they talk to WireGuard and netlink.

## Build

```sh
cargo build --release
sudo install -m 755 target/release/wgsrv /usr/bin/wgsrv
```

The client helper script expects the usual WireGuard tools plus `nc`, `timeout`,
`sudo`, `install`, and `mktemp`.

## Server Setup

Create a network:

```sh
sudo wgsrv network add wg0 --net4 10.23.0.0/24 --net6 fd23::/64 51820
```

This creates the WireGuard interface, generates the server key, and writes the
network to `/etc/wireguard/wgsrv.json`.

Bring networks up or down:

```sh
sudo wgsrv network up
sudo wgsrv network down
```

Pass a network name to affect only one interface:

```sh
sudo wgsrv network up wg0
sudo wgsrv network down wg0
```

List or inspect configured networks:

```sh
wgsrv network list
sudo wgsrv network show wg0
```

`network show` prints the private key, so treat its output accordingly.

## Register A Peer

This is the part `wgsrv` is really built around. On the server, start a
registration session for the network:

```sh
sudo wgsrv peer register wg0
```

By default this listens on `0.0.0.0:52001`. Use `--listen` to choose another
address:

```sh
sudo wgsrv peer register --listen 127.0.0.1:52001 wg0
```

If you want a WireGuard preshared key for this client, add
`--preshared-key`:

```sh
sudo wgsrv peer register --preshared-key wg0
```

The server will ask whether to send the preshared key over the registration
connection. That connection is not encrypted. If you answer no, the server
prints the key locally and the client script asks you to paste it.

On the client, run:

```sh
scripts/register-client.sh server.example.org laptop
```

The script generates a private key unless `PRIVATE_KEY` is already set, sends
the peer name and public key to the server, and prints the returned config. The
server registers the peer during that exchange and sends back the addresses,
server public key, endpoint, and allowed IPs. No manual copy/paste is needed.

If you choose to install the config, the script writes it with mode `600`. For
configs under `/etc/wireguard/*.conf`, it can also restart the matching
`wg-quick@...` systemd service.

You can include a registration port in the server argument:

```sh
scripts/register-client.sh server.example.org:52001 laptop
scripts/register-client.sh '[2001:db8::1]:52001' laptop
```

After registration, check peers on the server:

```sh
sudo wgsrv peer list wg0
sudo wgsrv peer show wg0 laptop
```

## systemd

The repository includes `wgsrv.service`, a oneshot unit that brings all
configured networks up on start and down on stop.

```sh
sudo install -m 644 wgsrv.service /etc/systemd/system/wgsrv.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgsrv.service
```

This is separate from `wg-quick@...`. The client helper asks about restarting
`wg-quick@<name>.service` because it installs a normal client config file under
`/etc/wireguard`.

## Settings File

The default settings file is:

```sh
/etc/wireguard/wgsrv.json
```

Use another file with:

```sh
wgsrv --settings ./wgsrv.json network list
```

The file contains networks, server private keys, and peer public keys. Keep it
private and back it up like any other WireGuard server configuration.

## License

MIT. See `LICENSE`.

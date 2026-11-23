# iroh-gateway

iroh-gateway is a TCP tunnel between a small public machine (the edge) and a private machine (the operator, for example a home cluster). The operator dials out to the edge over iroh (QUIC, peers identified by ed25519 key), so the private side needs no open port and no public address. Visitors connect to the edge, and their connections are carried through the tunnel to a target next to the operator. The design is in [the spec](docs/superpowers/specs/2026-11-23-iroh-gateway-design.md).

## Status

Tunnel core only: the edge binary, and the operator binary with a static configuration file. There is no Kubernetes integration yet.

## Build

```sh
direnv allow        # or: nix develop
cargo build --release
cargo test
```

The binaries are `target/release/iroh-gateway-edge` and `target/release/iroh-gateway-operator`.

## Quickstart

Everything on one machine, over loopback. Run every command below in the same terminal, from the repository root, one block after another.

1. Build, create both keys and note the two ids:

   ```sh
   cargo build --release
   EDGE=target/release/iroh-gateway-edge
   OPERATOR=target/release/iroh-gateway-operator
   EDGE_ID=$($EDGE id --key-file edge.key)
   OPERATOR_ID=$($OPERATOR id --key-file operator.key)
   echo "edge: $EDGE_ID"; echo "operator: $OPERATOR_ID"
   ```

2. Start something to expose, in the background (the `docs` directory, so the keys are not served):

   ```sh
   python3 -m http.server 3000 --bind 127.0.0.1 --directory docs >/dev/null 2>&1 &
   TARGET_PID=$!
   ```

3. Start the edge in the background, serving only that operator:

   ```sh
   $EDGE run --key-file edge.key --operator "$OPERATOR_ID" \
       --iroh-listen 127.0.0.1:7842 --public-bind 127.0.0.1 2>edge.log &
   EDGE_PID=$!
   ```

4. Write the operator configuration and start the operator in the background:

   ```sh
   cat > operator.toml <<EOF
   key_file = "operator.key"

   [[edge]]
   endpoint_id = "$EDGE_ID"
   address = "127.0.0.1:7842"

   [[edge.listener]]
   protocol = "tcp"
   port = 8080
   target = "127.0.0.1:3000"
   EOF
   $OPERATOR static --config operator.toml 2>operator.log &
   OPERATOR_PID=$!
   ```

5. Visit the target through the edge port (give the operator a moment to connect):

   ```sh
   sleep 2
   curl http://127.0.0.1:8080/
   ```

   You get the directory listing of `python3 -m http.server`. The edge and operator logs are in `edge.log` and `operator.log`.

6. Stop everything and remove what the quickstart created:

   ```sh
   kill $OPERATOR_PID $EDGE_PID $TARGET_PID
   wait
   rm -f edge.key operator.key operator.toml edge.log operator.log
   ```

On a real deployment the edge runs on the public machine with `--iroh-listen <public-ip>:7842` and the default `--public-bind ::`, the operator config names the edge's public address, and `port = 8080` is whatever public port you want. Key files must be backed up: the key is the identity. Both binaries log to stderr; set `RUST_LOG` to change the level (default `info`).

## `iroh-gateway-edge`

| Command | Flags (env) | Default |
|---|---|---|
| `id` | `--key-file` (`IROH_GATEWAY_EDGE_KEY_FILE`) | `/var/lib/iroh-gateway-edge/edge.key` |
| `run` | `--key-file` as above | |
| | `--operator <EndpointId>` (`IROH_GATEWAY_EDGE_OPERATOR`) | required |
| | `--iroh-listen <addr>` (`IROH_GATEWAY_EDGE_IROH_LISTEN`) | `0.0.0.0:7842` |
| | `--public-bind <ip>` (`IROH_GATEWAY_EDGE_PUBLIC_BIND`) | `::` |
| | `--max-connections <n>` (`IROH_GATEWAY_EDGE_MAX_CONNECTIONS`), 1 to 65536; about 400 KiB per connection in the worst case | `2048` |
| | `--tunnel-grace <duration>` (`IROH_GATEWAY_EDGE_TUNNEL_GRACE`), for example `5s` | `5s` |
| | `--relay <disabled\|n0\|URL>` (`IROH_GATEWAY_EDGE_RELAY`) | `disabled` |

`id` prints the EndpointId and a newline, nothing else, and creates the key file if it is missing. A malformed key file is an error and is never overwritten. `--public-bind ::` also accepts IPv4 on a dual-stack host. On a host with IPv6 disabled the bind fails and shows up as a listener bind error; set `--public-bind 0.0.0.0` there.

## `iroh-gateway-operator`

| Command | Flags | Default |
|---|---|---|
| `id` | `--key-file` | `operator.key` |
| `static` | `--config <file>` | required |

The static configuration file:

```toml
key_file = "operator.key"
relay = "disabled"             # optional; "disabled" (default), "n0", or a relay URL

[[edge]]
endpoint_id = "<edge EndpointId>"
address = "203.0.113.7:7842"   # optional when relay is not "disabled"

[[edge.listener]]
protocol = "tcp"
port = 8080
target = "127.0.0.1:3000"
```

Unknown fields, an edge listed twice, an edge without listeners, two listeners with the same protocol and port in one edge, and a missing `address` while `relay` is `disabled` are rejected at start.

## Trust

The visitor address a backend sees is only as trustworthy as the edge. It is for logging, not for access control. Each side pins the other's key: the edge serves only the operator named by `--operator`, and the operator connects only to the edges it lists.

## Relay mode

Relay mode is off by default (`disabled`): the operator reaches the edge at the `address` you give, and nothing else is contacted. Turn it on when the operator cannot reach the edge directly, for example when the edge has no stable address. Both sides must use the same value (`--relay` on the edge, `relay` in the operator config).

A relay learns the home IP, the edge's IP, and the size and timing of the relayed traffic. With `n0` it also sees address lookups from home. A relay cannot read or alter the traffic: it is encrypted end to end between the two keys.

## Known limitations

- **Addresses exchanged in direct mode.** iroh's QUIC NAT traversal cannot be switched off in iroh 1.5: even with relay mode disabled, each side tells the other its local interface addresses and sends probe packets to the addresses it is told. Port mapping (UPnP/NAT-PMP/PCP) is disabled. Mitigation: start the edge with `--iroh-listen <public-ip>:7842` instead of `0.0.0.0:7842`, since only a wildcard bind advertises every interface.
- **Stalled visitors are cut after 5 minutes.** If a visitor accepts no data for 300 seconds while data is waiting for it, the connection is aborted. Idle connections with nothing pending are not affected.
- **Half-closed connections are cut after 5 minutes of silence.** Once one side has finished sending, the connection is aborted if the other side sends nothing for 300 seconds.
- **TCP only.** UDP listeners are reported as a bind error in this version.
- **No metrics yet.** Both binaries log to stderr only.

## License

AGPL-3.0-or-later.

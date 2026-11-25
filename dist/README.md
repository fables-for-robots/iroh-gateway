# iroh-gateway edge

This tarball holds the public edge of iroh-gateway for one Linux architecture:
- `iroh-gateway-edge`: the edge, a static binary; it goes to `/usr/local/bin/`.
- `iroh-gateway-edge.service`: its hardened systemd unit; it goes to `/etc/systemd/system/`.
  The comment at its top gives the install commands and the command that prints the edge's id.
- `README.md`: this file. `LICENSE`: the GNU AGPL v3; the edge is AGPL-3.0-or-later.

The unit reads `/etc/iroh-gateway-edge/env`, which you write: `IROH_GATEWAY_EDGE_OPERATOR=<the operator's id>`.
The edge keeps its key in `/var/lib/iroh-gateway-edge/`. More: https://github.com/fables-for-robots/iroh-gateway

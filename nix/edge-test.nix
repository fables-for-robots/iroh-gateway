# A NixOS VM running the edge through nixosModules.edge. No operator holds the key below (a
# valid public key encoding), so the edge waits for one, which is all this test needs.
{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "iroh-gateway-edge";

  nodes.machine = { pkgs, ... }: {
    imports = [ self.nixosModules.edge ];
    services.iroh-gateway-edge = {
      enable = true;
      operator = "5866666666666666666666666666666666666666666666666666666666666666";
      metricsListen = "127.0.0.1:9090";
      openFirewall = true;
    };
    environment.systemPackages = [ pkgs.curl ];
  };

  testScript = ''
    import re


    def started_ids() -> list[str]:
        """The id of every "edge started" line in the unit's journal, oldest first."""
        log = machine.succeed("journalctl --no-pager -o cat -u iroh-gateway-edge.service")
        # tracing colours its output even when it goes to the journal.
        log = re.sub(r"\x1b\[[0-9;]*m", "", log)
        return re.findall(r"edge started.*\bid=([0-9a-f]{64})", log)


    machine.wait_for_unit("iroh-gateway-edge.service")
    machine.wait_for_open_port(9090, "127.0.0.1")

    with subtest("metrics are served and no session is up"):
        metrics = machine.succeed("curl -sSf http://127.0.0.1:9090/metrics")
        assert "iroh_gateway_edge_session_up 0" in metrics.splitlines(), metrics

    with subtest("the iroh endpoint is bound on UDP 7842"):
        machine.wait_until_succeeds("ss -lunH 'sport = :7842' | grep -q .")

    with subtest("the firewall lets UDP 7842 in"):
        machine.wait_for_unit("firewall.service")
        machine.succeed(
            "iptables -S nixos-fw | grep -E -- '-p udp .*--dport 7842 .*-j nixos-fw-accept'"
        )

    with subtest("the service runs as a dynamic user and keeps its key in its state directory"):
        dynamic = machine.succeed(
            "systemctl show -p DynamicUser --value iroh-gateway-edge.service"
        ).strip()
        assert dynamic == "yes", f"DynamicUser={dynamic}"
        machine.succeed("test -s /var/lib/private/iroh-gateway-edge/edge.key")

    with subtest("a restart keeps the id"):
        machine.wait_until_succeeds("journalctl -o cat -u iroh-gateway-edge.service | grep -q 'edge started'")
        first = started_ids()
        assert len(first) == 1, first
        machine.succeed("systemctl restart iroh-gateway-edge.service")
        machine.wait_for_unit("iroh-gateway-edge.service")
        machine.wait_until_succeeds(
            "test $(journalctl -o cat -u iroh-gateway-edge.service | grep -c 'edge started') -ge 2"
        )
        ids = started_ids()
        assert len(ids) == 2 and ids[0] == ids[1], ids
        machine.succeed("systemctl is-active iroh-gateway-edge.service")
  '';
}

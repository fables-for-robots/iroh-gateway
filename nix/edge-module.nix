# The iroh-gateway edge as a hardened systemd service, iroh-gateway-edge.service. Its
# hardening is the same, setting for setting, as dist/iroh-gateway-edge.service's.
{ self }:
{ config, lib, pkgs, utils, ... }:
let
  inherit (lib) mkOption types;
  cfg = config.services.iroh-gateway-edge;
  # "0.0.0.0:7842" and "[::]:7842" alike: the port is what follows the last colon.
  irohPort = lib.toInt (lib.last (lib.splitString ":" cfg.irohListen));
  args = [
    "run"
    "--operator" cfg.operator
    "--key-file" cfg.keyFile
    "--iroh-listen" cfg.irohListen
    "--public-bind" cfg.publicBind
    "--max-connections" (toString cfg.maxConnections)
    "--max-udp-flows" (toString cfg.maxUdpFlows)
    "--tunnel-grace" cfg.tunnelGrace
    "--relay" cfg.relay
  ]
  ++ lib.optionals (cfg.udpRateLimit != null) [ "--udp-rate-limit" (toString cfg.udpRateLimit) ]
  ++ lib.optionals (cfg.metricsListen != null) [ "--metrics-listen" cfg.metricsListen ]
  ++ cfg.extraArgs;
in {
  _file = ./edge-module.nix;
  # One key for nixosModules.edge and nixosModules.default, so importing both is harmless.
  key = "iroh-gateway#nixosModules.edge";

  options.services.iroh-gateway-edge = {
    enable = lib.mkEnableOption "the iroh-gateway edge, the public side of the tunnel";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.edge;
      defaultText = lib.literalExpression "iroh-gateway.packages.\${pkgs.stdenv.hostPlatform.system}.edge";
      description = "The iroh-gateway-edge package to run.";
    };

    operator = mkOption {
      type = types.str;
      example = "5866666666666666666666666666666666666666666666666666666666666666";
      description = ''
        EndpointId of the only operator this edge serves: 64 lowercase hexadecimal characters,
        as `iroh-gateway-operator id` prints it. Required when the edge is enabled.
      '';
    };

    keyFile = mkOption {
      type = types.str;
      default = "/var/lib/iroh-gateway-edge/edge.key";
      description = ''
        The edge's secret key, created there if it is missing; it fixes the edge's EndpointId.
        The default lies in the service's StateDirectory, which systemd keeps for its dynamic
        user. Another path must be readable (and, for the key to be created, its directory
        writable) by that dynamic user; arranging that is up to you.
      '';
    };

    irohListen = mkOption {
      type = types.strMatching ".*:[0-9]+";
      default = "0.0.0.0:7842";
      example = "[::]:7842";
      description = "UDP address (host:port) for the iroh endpoint the operator dials.";
    };

    publicBind = mkOption {
      type = types.str;
      default = "::";
      description = "Address the public listeners (the Gateway's ports) bind to.";
    };

    maxConnections = mkOption {
      type = types.ints.between 1 4096;
      default = 2048;
      description = "Maximum number of simultaneous visitor connections; each may hold about 400 KiB.";
    };

    maxUdpFlows = mkOption {
      type = types.ints.between 1 4096;
      default = 4096;
      description = ''
        Maximum number of UDP flows (one per visitor address and port); at the cap a new flow
        replaces the least recently used one.
      '';
    };

    udpRateLimit = mkOption {
      type = types.nullOr types.ints.positive;
      default = null;
      description = ''
        Most UDP bytes per second sent from visitors into the tunnel, counted as each packet's
        payload plus an 18-byte header per fragment; no limit when null.
      '';
    };

    tunnelGrace = mkOption {
      type = types.str;
      default = "5s";
      description = "How long listeners stay open without a tunnel, as a duration such as \"5s\".";
    };

    relay = mkOption {
      type = types.str;
      default = "disabled";
      example = "n0";
      description = ''"disabled", "n0" or an https relay URL; the operator must use the same.'';
    };

    metricsListen = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9090";
      description = "Address (host:port) to serve Prometheus metrics on, at /metrics; not served when null.";
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Whether to open the UDP port of `irohListen` in the firewall. Only that port: the public
        ports are the Gateway's, and opening them stays the administrator's to do.
      '';
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Further arguments appended to `iroh-gateway-edge run`.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = builtins.match "[0-9a-f]{64}" cfg.operator != null;
        message = ''
          services.iroh-gateway-edge.operator must be the operator's EndpointId, 64 lowercase
          hexadecimal characters, not "${cfg.operator}".
        '';
      }
    ];

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ irohPort ];

    systemd.services.iroh-gateway-edge = {
      description = "iroh-gateway edge";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = utils.escapeSystemdExecArgs ([ (lib.getExe cfg.package) ] ++ args);
        DynamicUser = "yes";
        StateDirectory = "iroh-gateway-edge";
        AmbientCapabilities = "CAP_NET_BIND_SERVICE";
        CapabilityBoundingSet = "CAP_NET_BIND_SERVICE";
        NoNewPrivileges = "yes";
        ProtectSystem = "strict";
        ProtectHome = "yes";
        PrivateTmp = "yes";
        PrivateDevices = "yes";
        ProtectKernelTunables = "yes";
        ProtectKernelModules = "yes";
        ProtectKernelLogs = "yes";
        ProtectControlGroups = "yes";
        ProtectClock = "yes";
        ProtectHostname = "yes";
        RestrictAddressFamilies = "AF_INET AF_INET6 AF_NETLINK AF_UNIX";
        RestrictNamespaces = "yes";
        RestrictRealtime = "yes";
        RestrictSUIDSGID = "yes";
        LockPersonality = "yes";
        MemoryDenyWriteExecute = "yes";
        SystemCallArchitectures = "native";
        SystemCallFilter = "@system-service";
        LimitNOFILE = 65536;
        Restart = "always";
        RestartSec = 2;
      };
    };
  };
}

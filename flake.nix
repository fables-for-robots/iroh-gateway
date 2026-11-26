{
  description = "iroh-gateway";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    systems.url = "github:nix-systems/default";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, systems, rust-overlay, ... }@inputs:
    let
      eachSystem = f:
        nixpkgs.lib.genAttrs (import systems) (system:
          f system (import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          }));
    in {
      devShells = eachSystem (system: pkgs: {
        default = pkgs.mkShell {
          packages = [
            (pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml)
            pkgs.haproxy
            # The operator's cluster tests: scripts/envtest-assets fetches an API server.
            pkgs.setup-envtest
            pkgs.kubectl
            # The chart, its test (scripts/chart-test.sh) and the kind cluster CI runs it in.
            pkgs.kubernetes-helm
            pkgs.kind
            pkgs.yq-go
            pkgs.shellcheck
            # The release workflow's checks: actionlint lints it, scripts/check-release-version.sh
            # reads cargo metadata with jq.
            pkgs.actionlint
            pkgs.jq
            # The operator's HTTPS tests make RSA and SEC1 keys with it.
            pkgs.openssl
          ];
        };
      });

      packages = eachSystem (system: pkgs:
        let
          inherit (pkgs) lib;
          # The Rust release of rust-toolchain.toml, without its development components.
          toolchain = pkgs.rust-bin.fromRustupToolchain {
            inherit ((lib.importTOML ./rust-toolchain.toml).toolchain) channel;
            profile = "minimal";
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          # Only what cargo reads, so editing docs, the chart or CI rebuilds nothing.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./proto/Cargo.toml
              ./proto/src
              ./edge/Cargo.toml
              ./edge/src
              ./operator/Cargo.toml
              ./operator/src
            ];
          };
          crate = dir: bin: args:
            rustPlatform.buildRustPackage ({
              pname = bin;
              inherit ((lib.importTOML ./${dir}/Cargo.toml).package) version;
              inherit src;
              cargoLock.lockFile = ./Cargo.lock;
              buildAndTestSubdir = dir;
              # The tests bind real UDP/QUIC and TCP sockets, which the build sandbox forbids;
              # CI runs them with cargo (.github/workflows/ci.yml).
              doCheck = false;
              meta = {
                description = "iroh-gateway ${dir}";
                license = lib.licenses.agpl3Plus;
                mainProgram = bin;
              };
            } // args);
          edge = crate "edge" "iroh-gateway-edge" { };
          # The operator runs HAProxy as a child process, found as `haproxy` on PATH unless
          # --haproxy-bin names another.
          operator = crate "operator" "iroh-gateway-operator" {
            nativeBuildInputs = [ pkgs.makeWrapper ];
            postInstall = ''
              wrapProgram $out/bin/iroh-gateway-operator \
                --prefix PATH : ${lib.makeBinPath [ pkgs.haproxy ]}
            '';
          };
        in {
          inherit edge operator;
          default = edge;
        });

      nixosModules = {
        edge = import ./nix/edge-module.nix { inherit self; };
        default = self.nixosModules.edge;
      };

      # The VM test needs KVM, which GitHub provides on its x86_64 Linux runners only.
      checks.x86_64-linux.edge-module = import ./nix/edge-test.nix {
        inherit self;
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
      };
    };
}

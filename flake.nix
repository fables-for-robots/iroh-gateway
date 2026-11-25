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
            # The operator's HTTPS tests make RSA and SEC1 keys with it.
            pkgs.openssl
          ];
        };
      });
    };
}

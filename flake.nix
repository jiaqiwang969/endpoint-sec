{
  description = "macOS Endpoint Security Rust bindings + codex-es-guard daemon";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      forDarwinSystems = f: nixpkgs.lib.genAttrs
        [ "aarch64-darwin" "x86_64-darwin" ]
        (system: f (import nixpkgs { inherit system; }));

      buildGuard = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "codex-es-guard";
        version = "0.1.0";
        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;

        cargoBuildFlags = [ "-p" "codex-es-guard" ];
        doCheck = false;

        buildInputs = [ pkgs.libiconv ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.apple-sdk_15
        ];

        nativeBuildInputs = [ pkgs.pkg-config ];

        # EndpointSecurity.framework is linked by endpoint-sec-sys via #[link].
        # We only need to add the system framework search path for the target,
        # NOT for build scripts (which would fail trying to find it).
        preConfigure = ''
          mkdir -p .cargo
          cat >> .cargo/config.toml << 'TOML'
          [target.aarch64-apple-darwin]
          rustflags = ["-C", "link-arg=-F/System/Library/Frameworks"]
          [target.x86_64-apple-darwin]
          rustflags = ["-C", "link-arg=-F/System/Library/Frameworks"]
          TOML
        '';

        postInstall = ''
          install -Dm644 codex-es-guard/es.plist $out/share/codex-es-guard/es.plist
        '';

        meta = {
          description = "Kernel-level file protection daemon for AI coding agents";
          license = pkgs.lib.licenses.mit;
          platforms = [ "aarch64-darwin" "x86_64-darwin" ];
        };
      };
    in
    {
      packages = forDarwinSystems (pkgs: {
        default = buildGuard pkgs;
        codex-es-guard = buildGuard pkgs;
      });

      darwinModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.codex-es-guard;
          signedBin = "/usr/local/bin/codex-es-guard";
        in {
          options.services.codex-es-guard = {
            enable = lib.mkEnableOption "codex-es-guard file protection daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "The codex-es-guard package to use.";
            };

            user = lib.mkOption {
              type = lib.types.str;
              default = "jqwang";
              description = "The user whose home directory contains the policy file.";
            };

            protectedZones = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              example = [ "/Users/jqwang/00-nixos-config" "/Users/jqwang/01-agent" ];
              description = "Directory prefixes to protect from deletion/move.";
            };
          };

          config = lib.mkIf cfg.enable {
            launchd.daemons.codex-es-guard = {
              serviceConfig = {
                Label = "com.jqwang.codex-es-guard";
                ProgramArguments = [ signedBin ];
                RunAtLoad = true;
                KeepAlive = true;
                StandardOutPath = "/tmp/codex-es-guard.log";
                StandardErrorPath = "/tmp/codex-es-guard.err";
                EnvironmentVariables = {
                  HOME = "/Users/${cfg.user}";
                };
              };
            };

            system.activationScripts.postActivation.text = let
              policyJson = builtins.toJSON {
                protected_zones = cfg.protectedZones;
                temporary_overrides = [];
              };
            in ''
              # === codex-es-guard activation ===
              ES_BIN="${cfg.package}/bin/codex-es-guard"
              ES_PLIST="${cfg.package}/share/codex-es-guard/es.plist"
              SIGNED="${signedBin}"

              # Copy and codesign (Nix store is read-only)
              if [ -f "$ES_BIN" ]; then
                mkdir -p /usr/local/bin
                cp -f "$ES_BIN" "$SIGNED"
                chmod 755 "$SIGNED"
                /usr/bin/codesign --entitlements "$ES_PLIST" --force -s - "$SIGNED" 2>/dev/null || true
                echo "codex-es-guard: signed at $SIGNED"

                # Restart daemon so it picks up the freshly signed binary
                /bin/launchctl kickstart -k system/com.jqwang.codex-es-guard 2>/dev/null || true
                echo "codex-es-guard: daemon restarted"
              fi

              # Create default policy if not exists
              POLICY_DIR="/Users/${cfg.user}/.codex"
              POLICY_FILE="$POLICY_DIR/es_policy.json"
              if [ ! -f "$POLICY_FILE" ]; then
                mkdir -p "$POLICY_DIR"
                echo '${policyJson}' > "$POLICY_FILE"
                chown ${cfg.user}:staff "$POLICY_FILE"
                echo "codex-es-guard: created default policy at $POLICY_FILE"
              fi

              # Ensure log directory
              mkdir -p "/Users/${cfg.user}/.codex/es-guard"
              chown ${cfg.user}:staff "/Users/${cfg.user}/.codex/es-guard"
            '';
          };
        };
    };
}

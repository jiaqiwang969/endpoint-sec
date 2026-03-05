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
          install -Dm755 codex-es-guard/es-guard-override $out/bin/es-guard-override
          install -Dm755 codex-es-guard/es-guard-quarantine $out/bin/es-guard-quarantine
          install -Dm755 codex-es-guard/es-guard-egress $out/bin/es-guard-egress
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
          daemonLabel = "dev.codex-es-guard";
          signedBin = "/usr/local/bin/codex-es-guard";
          homeDir = if pkgs.stdenv.isDarwin then "/Users/${cfg.user}" else "/home/${cfg.user}";
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
              description = "The user whose home directory contains the policy file.";
            };

            protectedZones = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              example = [ "/Users/me/projects" "/Users/me/important" ];
              description = "Directory prefixes to protect from deletion/move.";
            };

            sensitiveZones = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              example = [ "/Users/me/.codex" ];
              description = "Directory prefixes treated as sensitive data zones.";
            };

            sensitiveExportAllowZones = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              example = [ "/Users/me/.codex/es-guard/quarantine" ];
              description = "Allowed destination prefixes for exporting files from sensitive zones.";
            };

            execExfilToolBlocklist = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ "curl" "wget" "scp" "sftp" "rsync" "nc" "ncat" "netcat" ];
              description = "Executable names denied in AI context when exec gate is enabled.";
            };

            readGateEnabled = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable sensitive read gating (AUTH_OPEN).";
            };

            transferGateEnabled = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable sensitive transfer gating (copy/clone/link/exchange/rename).";
            };

            execGateEnabled = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Enable AUTH_EXEC hardening against exfiltration tools in AI context.";
            };

            taintTTLSeconds = lib.mkOption {
              type = lib.types.ints.positive;
              default = 600;
              description = "TTL in seconds for sensitive-read taint tracking.";
            };

            autoProtectHomeDigitChildrenDefault = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = ''
                Default value for `auto_protect_home_digit_children` when the
                policy file does not yet define it. When enabled, any first-level
                child directory under HOME whose name starts with a digit
                (e.g. ~/01-agent, ~/0x-lab) is treated as protected.
              '';
            };
          };

          config = lib.mkIf cfg.enable {
            launchd.daemons.codex-es-guard = {
              serviceConfig = {
                Label = daemonLabel;
                ProgramArguments = [ signedBin ];
                RunAtLoad = true;
                KeepAlive = true;
                StandardOutPath = "/tmp/codex-es-guard.log";
                StandardErrorPath = "/tmp/codex-es-guard.err";
                EnvironmentVariables = {
                  HOME = homeDir;
                };
              };
            };

            system.activationScripts.postActivation.text = let
              # Nix is the source of truth for static guard zones and DLP gate knobs.
              # temporary_overrides is runtime-only and managed by codex-es-guard root helper.
              protectedZonesJson = builtins.toJSON cfg.protectedZones;
              sensitiveZonesJson = builtins.toJSON cfg.sensitiveZones;
              sensitiveExportAllowZonesJson = builtins.toJSON cfg.sensitiveExportAllowZones;
              execExfilToolBlocklistJson = builtins.toJSON cfg.execExfilToolBlocklist;
              readGateEnabledJson = if cfg.readGateEnabled then "true" else "false";
              transferGateEnabledJson = if cfg.transferGateEnabled then "true" else "false";
              execGateEnabledJson = if cfg.execGateEnabled then "true" else "false";
              taintTTLSecondsJson = builtins.toJSON cfg.taintTTLSeconds;
              autoProtectHomeDigitChildrenDefaultJson =
                if cfg.autoProtectHomeDigitChildrenDefault then "true" else "false";
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

                # Install helper script
                cp -f "${cfg.package}/bin/es-guard-override" /usr/local/bin/es-guard-override
                chmod 755 /usr/local/bin/es-guard-override
                cp -f "${cfg.package}/bin/es-guard-quarantine" /usr/local/bin/es-guard-quarantine
                chmod 755 /usr/local/bin/es-guard-quarantine
                cp -f "${cfg.package}/bin/es-guard-egress" /usr/local/bin/es-guard-egress
                chmod 755 /usr/local/bin/es-guard-egress

                # Restart daemon so it picks up the freshly signed binary
                /bin/launchctl kickstart -k system/${daemonLabel} 2>/dev/null || true
                echo "codex-es-guard: daemon restarted"
              fi

              # Root-owned runtime override store (authoritative).
              RUNTIME_OVERRIDE_DIR="/var/db/codex-es-guard"
              mkdir -p "$RUNTIME_OVERRIDE_DIR"
              chown root:wheel "$RUNTIME_OVERRIDE_DIR"
              chmod 700 "$RUNTIME_OVERRIDE_DIR"

              # Sync static policy from Nix config (always update).
              # temporary_overrides field is mirror-only and filled by daemon.
              POLICY_DIR="${homeDir}/.codex"
              POLICY_FILE="$POLICY_DIR/es_policy.json"
              mkdir -p "$POLICY_DIR"
              chown ${cfg.user}:staff "$POLICY_DIR"

              EXISTING_TRUSTED_TOOLS="null"
              EXISTING_AI_PATTERNS="null"
              EXISTING_ALLOW_VCS_META_IN_AI="null"
              EXISTING_ALLOW_TRUSTED_IN_AI="null"
              EXISTING_AUTO_PROTECT_HOME_DIGIT_CHILDREN="null"
              EXISTING_TRUSTED_TOOL_IDENTITIES="null"
              EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH="null"
              if [ -f "$POLICY_FILE" ]; then
                EXISTING_TRUSTED_TOOLS=$(${pkgs.jq}/bin/jq -c '.trusted_tools // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_AI_PATTERNS=$(${pkgs.jq}/bin/jq -c '.ai_agent_patterns // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_ALLOW_VCS_META_IN_AI=$(${pkgs.jq}/bin/jq -c '.allow_vcs_metadata_in_ai_context // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_ALLOW_TRUSTED_IN_AI=$(${pkgs.jq}/bin/jq -c '.allow_trusted_tools_in_ai_context // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_AUTO_PROTECT_HOME_DIGIT_CHILDREN=$(${pkgs.jq}/bin/jq -c '.auto_protect_home_digit_children // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_TRUSTED_TOOL_IDENTITIES=$(${pkgs.jq}/bin/jq -c '.trusted_tool_identities // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH=$(${pkgs.jq}/bin/jq -c '.trusted_identity_require_cdhash // null' "$POLICY_FILE" 2>/dev/null || echo "null")
              fi

              # Fail-closed guard: when trusted_tool_identities is missing/empty,
              # initialize a minimal signed identity set so git/jj/cargo/xcrun metadata
              # operations do not get stuck in TRUST_IDENTITY_MISMATCH.
              DEFAULT_TRUSTED_TOOL_IDENTITIES="[]"
              if [ "$EXISTING_TRUSTED_TOOL_IDENTITIES" = "null" ] || [ "$EXISTING_TRUSTED_TOOL_IDENTITIES" = "[]" ]; then
                for TOOL in git jj cargo xcrun; do
                  TOOL_PATH="$(command -v "$TOOL" 2>/dev/null || true)"
                  if [ -z "$TOOL_PATH" ]; then
                    continue
                  fi

                  CANONICAL_PATH="$TOOL_PATH"
                  if [ -x /usr/bin/python3 ]; then
                    CANONICAL_PATH="$(/usr/bin/python3 - "$TOOL_PATH" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
)"
                  fi
                  if [ ! -x "$CANONICAL_PATH" ]; then
                    continue
                  fi

                  CODESIGN_REPORT="$(
                    /usr/bin/codesign -dv --verbose=4 "$CANONICAL_PATH" 2>&1 || true
                  )"
                  SIGNING_IDENTIFIER="$(printf '%s\n' "$CODESIGN_REPORT" | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')"
                  if [ -z "$SIGNING_IDENTIFIER" ]; then
                    continue
                  fi
                  TEAM_IDENTIFIER="$(printf '%s\n' "$CODESIGN_REPORT" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"

                  ENTRY="$(${pkgs.jq}/bin/jq -cn \
                    --arg path "$CANONICAL_PATH" \
                    --arg signingIdentifier "$SIGNING_IDENTIFIER" \
                    --arg teamIdentifier "$TEAM_IDENTIFIER" \
                    '{path: $path, signing_identifier: $signingIdentifier}
                     + (if ($teamIdentifier | length) > 0 and $teamIdentifier != "not set"
                        then {team_identifier: $teamIdentifier}
                        else {}
                        end)'
                  )"
                  DEFAULT_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -cn \
                    --argjson current "$DEFAULT_TRUSTED_TOOL_IDENTITIES" \
                    --argjson entry "$ENTRY" \
                    '$current + [$entry]'
                  )"
                done
                DEFAULT_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -c 'unique_by(.path)' <<<"$DEFAULT_TRUSTED_TOOL_IDENTITIES")"
              fi

              ${pkgs.jq}/bin/jq -n \
                --argjson zones '${protectedZonesJson}' \
                --argjson sensitiveZones '${sensitiveZonesJson}' \
                --argjson sensitiveExportAllowZones '${sensitiveExportAllowZonesJson}' \
                --argjson execExfilToolBlocklist '${execExfilToolBlocklistJson}' \
                --argjson readGateEnabled ${readGateEnabledJson} \
                --argjson transferGateEnabled ${transferGateEnabledJson} \
                --argjson execGateEnabled ${execGateEnabledJson} \
                --argjson taintTTLSeconds '${taintTTLSecondsJson}' \
                --argjson trustedTools "$EXISTING_TRUSTED_TOOLS" \
                --argjson aiPatterns "$EXISTING_AI_PATTERNS" \
                --argjson allowVcsMetaInAi "$EXISTING_ALLOW_VCS_META_IN_AI" \
                --argjson allowTrustedInAi "$EXISTING_ALLOW_TRUSTED_IN_AI" \
                --argjson autoProtectHomeDigitChildren "$EXISTING_AUTO_PROTECT_HOME_DIGIT_CHILDREN" \
                --argjson trustedToolIdentities "$EXISTING_TRUSTED_TOOL_IDENTITIES" \
                --argjson trustedToolIdentitiesDefault "$DEFAULT_TRUSTED_TOOL_IDENTITIES" \
                --argjson trustedIdentityRequireCdhash "$EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH" \
                --argjson autoProtectHomeDigitChildrenDefault ${autoProtectHomeDigitChildrenDefaultJson} \
                '({protected_zones: $zones, temporary_overrides: []}
                  + {sensitive_zones: $sensitiveZones}
                  + {sensitive_export_allow_zones: $sensitiveExportAllowZones}
                  + {exec_exfil_tool_blocklist: $execExfilToolBlocklist}
                  + {read_gate_enabled: $readGateEnabled}
                  + {transfer_gate_enabled: $transferGateEnabled}
                  + {exec_gate_enabled: $execGateEnabled}
                  + {taint_ttl_seconds: $taintTTLSeconds}
                  + {auto_protect_home_digit_children: (
                      if $autoProtectHomeDigitChildren == null
                      then $autoProtectHomeDigitChildrenDefault
                      else $autoProtectHomeDigitChildren
                      end
                    )}
                  + (if $trustedTools == null then {} else {trusted_tools: $trustedTools} end)
                  + (if $trustedToolIdentities == null or $trustedToolIdentities == []
                     then {trusted_tool_identities: $trustedToolIdentitiesDefault}
                     else {trusted_tool_identities: $trustedToolIdentities}
                     end)
                  + (if $aiPatterns == null then {} else {ai_agent_patterns: $aiPatterns} end)
                  + (if $allowVcsMetaInAi == null then {} else {allow_vcs_metadata_in_ai_context: $allowVcsMetaInAi} end)
                  + (if $allowTrustedInAi == null then {} else {allow_trusted_tools_in_ai_context: $allowTrustedInAi} end)
                  + (if $trustedIdentityRequireCdhash == null then {} else {trusted_identity_require_cdhash: $trustedIdentityRequireCdhash} end))' \
                > "$POLICY_FILE"
              chown ${cfg.user}:staff "$POLICY_FILE"
              echo "codex-es-guard: policy synced ($(echo '${protectedZonesJson}' | ${pkgs.jq}/bin/jq length) zones)"

              # Ensure log directory
              mkdir -p "${homeDir}/.codex/es-guard"
              chown ${cfg.user}:staff "${homeDir}/.codex/es-guard"
              chmod 700 "${homeDir}/.codex/es-guard"
              mkdir -p "${homeDir}/.codex/es-guard/override-requests"
              chown ${cfg.user}:staff "${homeDir}/.codex/es-guard/override-requests"
              chmod 700 "${homeDir}/.codex/es-guard/override-requests"
            '';
          };
        };
    };
}

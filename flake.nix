{
  description = "macOS Endpoint Security Rust bindings + agentsmith-rs daemon";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      forDarwinSystems = f: nixpkgs.lib.genAttrs
        [ "aarch64-darwin" "x86_64-darwin" ]
        (system: f (import nixpkgs { inherit system; }));

      buildGuard = pkgs: pkgs.rustPlatform.buildRustPackage {
        pname = "agentsmith-rs";
        version = "0.1.0";
        src = ./.;

        cargoLock.lockFile = ./Cargo.lock;

        cargoBuildFlags = [ "-p" "agentsmith-rs" ];
        doCheck = false;

        buildInputs = [ pkgs.libiconv ] ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
          pkgs.apple-sdk_15
        ];

        nativeBuildInputs = [ pkgs.pkg-config ];

        # EndpointSecurity.framework is linked by agentsmith-rs-sys via #[link].
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
          install -Dm644 agentsmith-rs/agentsmith.plist $out/share/agentsmith-rs/agentsmith.plist
          install -Dm755 agentsmith-rs/agentsmith-override $out/bin/agentsmith-override
          install -Dm755 agentsmith-rs/agentsmith-quarantine $out/bin/agentsmith-quarantine
          install -Dm755 agentsmith-rs/agentsmith-egress $out/bin/agentsmith-egress
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
        agentsmith-rs = buildGuard pkgs;
      });

      darwinModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.agentsmith-rs;
          daemonLabel = "dev.agentsmith-rs";
          signedBin = "/usr/local/bin/agentsmith-rs";
          homeDir = if pkgs.stdenv.isDarwin then "/Users/${cfg.user}" else "/home/${cfg.user}";
        in {
          options.services.agentsmith-rs = {
            enable = lib.mkEnableOption "agentsmith-rs file protection daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              description = "The agentsmith-rs package to use.";
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
              example = [ "/Users/me/.agentsmith-rs/guard/quarantine" ];
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
            launchd.daemons.agentsmith-rs = {
              serviceConfig = {
                Label = daemonLabel;
                ProgramArguments = [ signedBin ];
                RunAtLoad = true;
                KeepAlive = true;
                StandardOutPath = "/tmp/agentsmith-rs.log";
                StandardErrorPath = "/tmp/agentsmith-rs.err";
                EnvironmentVariables = {
                  HOME = homeDir;
                };
              };
            };

            system.activationScripts.postActivation.text = let
              # Nix is the source of truth for static guard zones and DLP gate knobs.
              # temporary_overrides is runtime-only and managed by agentsmith-rs root helper.
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
              # === agentsmith-rs activation ===
              ES_BIN="${cfg.package}/bin/agentsmith-rs"
              ES_PLIST="${cfg.package}/share/agentsmith-rs/agentsmith.plist"
              SIGNED="${signedBin}"
              NEW_POLICY_DIR="${homeDir}/.agentsmith-rs"
              NEW_POLICY_FILE="$NEW_POLICY_DIR/policy.json"
              NEW_GUARD_DIR="$NEW_POLICY_DIR/guard"
              OLD_POLICY_DIR="${homeDir}/.codex"
              OLD_POLICY_FILE="$OLD_POLICY_DIR/es_policy.json"
              OLD_GUARD_DIR="$OLD_POLICY_DIR/es-guard"

              # Copy and codesign (Nix store is read-only)
              if [ -f "$ES_BIN" ]; then
                mkdir -p /usr/local/bin
                cp -f "$ES_BIN" "$SIGNED"
                chmod 755 "$SIGNED"
                /usr/bin/codesign --entitlements "$ES_PLIST" --force -s - "$SIGNED" 2>/dev/null || true
                echo "agentsmith-rs: signed at $SIGNED"

                # Install helper script
                cp -f "${cfg.package}/bin/agentsmith-override" /usr/local/bin/agentsmith-override
                chmod 755 /usr/local/bin/agentsmith-override
                cp -f "${cfg.package}/bin/agentsmith-quarantine" /usr/local/bin/agentsmith-quarantine
                chmod 755 /usr/local/bin/agentsmith-quarantine
                cp -f "${cfg.package}/bin/agentsmith-egress" /usr/local/bin/agentsmith-egress
                chmod 755 /usr/local/bin/agentsmith-egress

                # Restart daemon so it picks up the freshly signed binary
                /bin/launchctl kickstart -k system/${daemonLabel} 2>/dev/null || true
                echo "agentsmith-rs: daemon restarted"
              fi

              # Root-owned runtime override store (authoritative).
              RUNTIME_OVERRIDE_DIR="/var/db/agentsmith-rs"
              mkdir -p "$RUNTIME_OVERRIDE_DIR"
              chown root:wheel "$RUNTIME_OVERRIDE_DIR"
              chmod 700 "$RUNTIME_OVERRIDE_DIR"

              # One-time migration from legacy Codex guard paths.
              mkdir -p "$NEW_POLICY_DIR" "$NEW_GUARD_DIR"
              chown ${cfg.user}:staff "$NEW_POLICY_DIR" "$NEW_GUARD_DIR"
              chmod 700 "$NEW_POLICY_DIR" "$NEW_GUARD_DIR"

              if [ -f "$OLD_POLICY_FILE" ] && [ ! -f "$NEW_POLICY_FILE" ]; then
                cp -f "$OLD_POLICY_FILE" "$NEW_POLICY_FILE"
                chown ${cfg.user}:staff "$NEW_POLICY_FILE"
                chmod 600 "$NEW_POLICY_FILE"
              fi

              if [ -d "$OLD_GUARD_DIR" ]; then
                if command -v rsync >/dev/null 2>&1; then
                  rsync -a --ignore-existing "$OLD_GUARD_DIR"/ "$NEW_GUARD_DIR"/ || true
                else
                  cp -R -n "$OLD_GUARD_DIR"/. "$NEW_GUARD_DIR"/ 2>/dev/null || true
                fi
                chown ${cfg.user}:staff "$NEW_GUARD_DIR" || true
              fi

              # Sync static policy from Nix config (always update).
              # temporary_overrides field is mirror-only and filled by daemon.
              POLICY_DIR="$NEW_POLICY_DIR"
              POLICY_FILE="$NEW_POLICY_FILE"
              mkdir -p "$POLICY_DIR"
              chown ${cfg.user}:staff "$POLICY_DIR"

              EXISTING_TRUSTED_TOOLS="null"
              EXISTING_AI_PATTERNS="null"
              EXISTING_ALLOW_VCS_META_IN_AI="null"
              EXISTING_ALLOW_TRUSTED_IN_AI="null"
              EXISTING_AUTO_PROTECT_HOME_DIGIT_CHILDREN="null"
              EXISTING_TRUSTED_TOOL_IDENTITIES="null"
              EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH="null"
              EXISTING_AUDIT_ONLY_MODE="null"
              if [ -f "$POLICY_FILE" ]; then
                EXISTING_TRUSTED_TOOLS=$(${pkgs.jq}/bin/jq -c '.trusted_tools // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_AI_PATTERNS=$(${pkgs.jq}/bin/jq -c '.ai_agent_patterns // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_ALLOW_VCS_META_IN_AI=$(${pkgs.jq}/bin/jq -c '.allow_vcs_metadata_in_ai_context // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_ALLOW_TRUSTED_IN_AI=$(${pkgs.jq}/bin/jq -c '.allow_trusted_tools_in_ai_context // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_AUTO_PROTECT_HOME_DIGIT_CHILDREN=$(${pkgs.jq}/bin/jq -c '.auto_protect_home_digit_children // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_TRUSTED_TOOL_IDENTITIES=$(${pkgs.jq}/bin/jq -c '.trusted_tool_identities // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH=$(${pkgs.jq}/bin/jq -c '.trusted_identity_require_cdhash // null' "$POLICY_FILE" 2>/dev/null || echo "null")
                EXISTING_AUDIT_ONLY_MODE=$(${pkgs.jq}/bin/jq -c '.audit_only_mode // null' "$POLICY_FILE" 2>/dev/null || echo "null")
              fi

              # Trusted identity bootstrap + top-up:
              # 1) when identities are missing/empty, seed minimal signed identities.
              # 2) when identities already exist, top-up missing tool coverage for
              #    git/jj/cargo/xcrun without overwriting existing entries.
              DISCOVERED_TRUSTED_TOOL_IDENTITIES="[]"
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
                  --arg tool "$TOOL" \
                  --arg path "$CANONICAL_PATH" \
                  --arg signingIdentifier "$SIGNING_IDENTIFIER" \
                  --arg teamIdentifier "$TEAM_IDENTIFIER" \
                  '{tool: $tool, path: $path, signing_identifier: $signingIdentifier}
                   + (if ($teamIdentifier | length) > 0 and $teamIdentifier != "not set"
                      then {team_identifier: $teamIdentifier}
                      else {}
                      end)'
                )"
                DISCOVERED_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -cn \
                  --argjson current "$DISCOVERED_TRUSTED_TOOL_IDENTITIES" \
                  --argjson entry "$ENTRY" \
                  '$current + [$entry]'
                )"
              done
              DISCOVERED_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -c 'unique_by(.path)' <<<"$DISCOVERED_TRUSTED_TOOL_IDENTITIES")"
              DEFAULT_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -c 'map(del(.tool))' <<<"$DISCOVERED_TRUSTED_TOOL_IDENTITIES")"

              MERGED_TRUSTED_TOOL_IDENTITIES="$EXISTING_TRUSTED_TOOL_IDENTITIES"
              if [ "$MERGED_TRUSTED_TOOL_IDENTITIES" = "null" ] || [ "$MERGED_TRUSTED_TOOL_IDENTITIES" = "[]" ]; then
                MERGED_TRUSTED_TOOL_IDENTITIES="$DEFAULT_TRUSTED_TOOL_IDENTITIES"
              elif ! ${pkgs.jq}/bin/jq -e 'type == "array"' <<<"$MERGED_TRUSTED_TOOL_IDENTITIES" >/dev/null 2>&1; then
                MERGED_TRUSTED_TOOL_IDENTITIES="$DEFAULT_TRUSTED_TOOL_IDENTITIES"
              else
                EXISTING_IDENTITY_TOOLS="$(${pkgs.jq}/bin/jq -c \
                  '[.[]? | .path? | strings | split("/") | last] | unique' \
                  <<<"$MERGED_TRUSTED_TOOL_IDENTITIES"
                )"
                TOPUP_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -cn \
                  --argjson discovered "$DISCOVERED_TRUSTED_TOOL_IDENTITIES" \
                  --argjson existingTools "$EXISTING_IDENTITY_TOOLS" \
                  '$discovered
                   | map(select(.tool as $tool | ($existingTools | index($tool)) == null))
                   | map(del(.tool))'
                )"
                MERGED_TRUSTED_TOOL_IDENTITIES="$(${pkgs.jq}/bin/jq -cn \
                  --argjson existing "$MERGED_TRUSTED_TOOL_IDENTITIES" \
                  --argjson topup "$TOPUP_TRUSTED_TOOL_IDENTITIES" \
                  '($existing + $topup) | unique_by(.path)'
                )"
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
                --argjson trustedToolIdentities "$MERGED_TRUSTED_TOOL_IDENTITIES" \
                --argjson trustedIdentityRequireCdhash "$EXISTING_TRUSTED_IDENTITY_REQUIRE_CDHASH" \
                --argjson auditOnlyMode "$EXISTING_AUDIT_ONLY_MODE" \
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
                  + (if $trustedToolIdentities == null then {} else {trusted_tool_identities: $trustedToolIdentities} end)
                  + (if $aiPatterns == null then {} else {ai_agent_patterns: $aiPatterns} end)
                  + (if $allowVcsMetaInAi == null then {} else {allow_vcs_metadata_in_ai_context: $allowVcsMetaInAi} end)
                  + (if $allowTrustedInAi == null then {} else {allow_trusted_tools_in_ai_context: $allowTrustedInAi} end)
                  + (if $trustedIdentityRequireCdhash == null then {} else {trusted_identity_require_cdhash: $trustedIdentityRequireCdhash} end)
                  + (if $auditOnlyMode == null then {} else {audit_only_mode: $auditOnlyMode} end))' \
                > "$POLICY_FILE"
              chown ${cfg.user}:staff "$POLICY_FILE"
              echo "agentsmith-rs: policy synced ($(echo '${protectedZonesJson}' | ${pkgs.jq}/bin/jq length) zones)"

              # Ensure log directory
              mkdir -p "$NEW_GUARD_DIR"
              chown ${cfg.user}:staff "$NEW_GUARD_DIR"
              chmod 700 "$NEW_GUARD_DIR"
              mkdir -p "$NEW_GUARD_DIR/override-requests"
              chown ${cfg.user}:staff "$NEW_GUARD_DIR/override-requests"
              chmod 700 "$NEW_GUARD_DIR/override-requests"
            '';
          };
        };
    };
}

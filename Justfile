default:
    just --list

# `cargo publish`, with `--dry-run` by default, use `just publish ""` to actually do it.
publish arg="--dry-run":
    git describe --exact-match --tags $(git log -n1 --pretty='%h')
    cargo publish {{ arg }} -p agentsmith-rs-sys
    cargo publish {{ arg }} -p agentsmith-rs-core

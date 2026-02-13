_default:
  @just --list --unsorted

# Build the library
build:
  cargo build

# Run all tests
test:
  cargo test

# Check formatting and clippy
lint:
  cargo clippy
  cargo fmt --check

# Format code
reformat:
  cargo fmt

# Dry run publish to crates.io
dryrun:
  cargo publish --dry-run

# Publish to crates.io
publish:
  cargo publish

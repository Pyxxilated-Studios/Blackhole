# Contributing

## Commits

Mostly these should follow the [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) style. This is ensured by
the CI.

## Releases

You will need `cargo-release` and `git-cliff`: `cargo install cargo-release git-cliff`
Bump the version in `Cargo.toml`, and `client/package.json`, then dry run the release with `cargo release`.

Ensure everything is fine, and then run `cargo release --execute`.

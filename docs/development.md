# Development

Run the commands below from the repository root. Install Rust and Cargo first;
the minimum Rust version is declared in [`Cargo.toml`](../Cargo.toml).

## Build and test

```sh
cargo build --locked
cargo test --locked
cargo fmt -- --check
cargo clippy --examples -- -D warnings
```

The [usage guide](usage.md) walks through the runnable examples:

```sh
cargo run --locked --example attributes
cargo run --locked --example issuance
cargo run --locked --example swap
```

Generate local Rust API documentation with:

```sh
cargo doc --no-deps --open
```

## Benchmarks

The benchmark harness uses Rust's nightly-only `test` feature:

```sh
rustup toolchain install nightly
cargo +nightly bench --locked
```

Benchmark implementations live in [`benches/`](../benches/).

## WebAssembly and JavaScript bindings

Install [`wasm-pack`](https://wasm-bindgen.github.io/wasm-pack/), then choose a
JavaScript target. For browser ES modules:

```sh
wasm-pack build --target web
```

For Node.js CommonJS modules:

```sh
wasm-pack build --target nodejs
```

Both commands generate a package under `pkg/`, containing the WebAssembly binary,
JavaScript bindings, and package metadata. Each build replaces the default output;
use `--out-dir` to keep separate packages. See the
[`wasm-pack build` reference](https://wasm-bindgen.github.io/wasm-pack/book/commands/build.html)
for target and output options. The binding implementations are in
[`src/wasm.rs`](../src/wasm.rs).

To check that the Rust library builds for WebAssembly without generating the
JavaScript package:

```sh
rustup target add wasm32-unknown-unknown
cargo build --locked --target wasm32-unknown-unknown --release
```

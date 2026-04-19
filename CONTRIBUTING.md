# Contributing to Actix Web CSP

Thanks for taking a look at the project.

The goal here is not just to keep the crate working, but to keep it dependable as a security-focused library. That means we care about API clarity, validation behavior, feature-flag coverage, and release hygiene alongside the usual code quality work.

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/hun756/actix_web_csp.git
   cd actix_web_csp
   ```

2. **Install Rust** (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Use the current MSRV or newer**:
   ```bash
   rustup toolchain install 1.85.0
   ```

4. **Run tests**:
   ```bash
   cargo test
   ```

5. **Run examples**:
   ```bash
   cargo run --example real_world_test_fixed
   cargo run --example csp_security_tester
   ```

## Testing

- Run the default suite: `cargo test`
- Run the full feature matrix: `cargo test --all-features`
- Run strict semantic validation tests: `cargo test --features extended-validation`
- Verify no-default-features compatibility: `cargo check --no-default-features`
- Run benchmarks: `cargo bench`
- Exercise the security example: `cargo run --example csp_security_tester`

## Code Style

- Format code: `cargo fmt --check`
- Check lints: `cargo clippy --all-targets --all-features -- -D warnings`
- Keep docs, examples, and feature-flag behavior in sync with the code
- Prefer adding tests for bug fixes and policy semantics, not just happy-path behavior

## Dependency Hygiene

- Dependency policy is checked with `cargo-deny`
- CI validates the supported feature matrix and the current MSRV
- If a dependency upgrade changes MSRV or behavior, call that out explicitly in the PR

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add or update tests
4. Run the quality commands locally
5. Submit a pull request with a short explanation of behavior changes

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- Include reproduction steps and policy snippets when relevant
- For security-sensitive reports, follow [SECURITY.md](SECURITY.md)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

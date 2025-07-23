# Contributing to Actix Web CSP

We welcome contributions! Here's how to get started.

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

3. **Run tests**:
   ```bash
   cargo test
   ```

4. **Run examples**:
   ```bash
   cargo run --example real_world_test_fixed
   cargo run --example csp_security_tester
   ```

## Testing

- Run all tests: `cargo test`
- Run integration tests: `cargo test integration_tests`
- Run benchmarks: `cargo bench`
- Security audit: `cargo run --example csp_security_tester`

## Code Style

- Format code: `cargo fmt`
- Check lints: `cargo clippy`
- Document public APIs thoroughly

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Reporting Issues

- Use GitHub Issues for bug reports
- Include reproduction steps
- For security issues, email directly

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

# Kestrel

Kestrel is a lightweight, high-throughput secret scanner for high-impact credentials, built to scan filesystems at scale with zero inline verification.

## Code guidelines

- No trivial comments
- Minimal bloat (KISS, DRY, SRP)
- No unnecessary state (variables, fields, arguments)
- Each line of code should justify its existence
- Follow Rust idioms and best practices
- Latest Rust features can be used
- Descriptive variable and function names
- No wildcard imports
- Import types at top of file and use short names everywhere (e.g. `use std::sync::Arc;` then `Arc<T>`, never `std::sync::Arc<T>` inline)
- Keep consts at top of file, right after imports
- No inline magic numbers or strings
- Explicit error handling with `Result<T, E>` over panics
- Use `anyhow` when the specific error is not as important
- Use custom error types with `thiserror` for domain-specific errors (rule parsing, scan failures)
- Be mindful of allocations in hot paths — the scan loop runs over tens of GB per batch; avoid per-match allocation, prefer borrowing from the mmap'd buffer
- Try solving with existing dependencies before adding new ones
- Prefer well-maintained crates from crates.io
- Prefer structured logging (wide logs with useful fields: bytes scanned, match count, duration, throughput)
- Provide helpful error messages
- Place unit tests in the same file using `#[cfg(test)]` modules
- Use `#[test_case]` when writing tests, and use snake_case for naming the tests
- No bullshit tests (e.g. tautologies)
- Make sure tests are not flaky (no weird sleeps)
- In tests, const error/status messages and assert against the shared constant
- Add `#[derive(Copy)]` only on structs with 1 primitive field

## Commits

- No conventional commits; messages are concise and focused, with bullet points only when needed
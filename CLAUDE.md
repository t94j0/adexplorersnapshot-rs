# Development Notes

## Build & Test

```bash
cargo build
cargo test
cargo run -- ./data/snapshot.bak -o /tmp/output.tar.gz
```

Inspect output:
```bash
cd /tmp && tar -xzf output.tar.gz && chmod 644 *.json
cat domains.json | python3 -m json.tool
```

## Test Data

Use `./data/snapshot.bak` for testing. It's a small AD snapshot with basic objects.

## GitHub Workflow

1. Create branch: `git checkout -b fix/issue-N-description`
2. Make changes, run tests
3. Commit: `git commit -m "Short description\n\nDetails\n\nFixes #N"`
4. Push: `git push -u origin fix/issue-N-description`
5. Create PR: `gh pr create --title "Title" --body "..."`
6. Watch checks: `gh pr checks N --watch`
7. Merge: `gh pr merge N --merge`
8. Return to master: `git checkout master && git pull`

## PR Template

```bash
gh pr create --title "Title here" --body "$(cat <<'EOF'
## Summary
- Change 1
- Change 2

## Test plan
- [ ] `cargo test` passes
- [ ] `cargo build --release` succeeds
- [ ] Tested with ./data/snapshot.bak

Fixes #N
EOF
)"
```

## Debugging Parser Output

Add temporary debug output to inspect parsed data:
```rust
eprintln!("DEBUG: value = {:?}", some_value);
```

Run and filter:
```bash
cargo run -- ./data/snapshot.bak -o /tmp/test.tar.gz 2>&1 | grep DEBUG
```

## Project Structure

- `src/parser/` - AD snapshot parsing
- `src/output/bloodhound/` - BloodHound JSON output (domains.rs, users.rs, computers.rs, etc.)
- `src/security_descriptor/` - SDDL/ACE parsing
- `src/sid/` - SID handling
- `src/guid/` - GUID handling

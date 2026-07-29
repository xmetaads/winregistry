## What changed

Describe the user-visible outcome and why this shape is safe.

## Registry safety

- [ ] No mutation path was added or changed.
- [ ] Or: policy is checked before prompting/writing, dry-run and JSON are
      supported, undo is complete, partial failure rolls back, and both WOW64
      views are handled or explicitly rejected.

## Evidence

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] Relevant unit and CLI contract tests
- [ ] `python scripts/check_site.py` and `python scripts/check_vercel.py`
      when the website changed
- [ ] Documentation and changelog updated for user-visible behavior

Include exact commands, relevant output, and any test that requires an
unelevated Windows account.


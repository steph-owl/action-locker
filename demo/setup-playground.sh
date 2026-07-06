#!/usr/bin/env bash
# Build a scratch playground for recording demo/demo.tape.
#
# Expects the demo repo checked out as a sibling of this repo:
#   ../action-locker-demo
#
# The playground is the demo app rewound to its "before" state: mutable
# tag refs, no lockfile, no vendored actions — so the recording shows the
# full lock -> rewrite -> vendor -> verify lifecycle happening for real.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="${ROOT}/../action-locker-demo"
PLAY="/tmp/action-locker-playground"

[ -d "$DEMO" ] || { echo "error: expected demo repo at $DEMO" >&2; exit 1; }

rm -rf "$PLAY"
cp -r "$DEMO" "$PLAY"
cp "$ROOT/action_locker.py" "$PLAY/"

# A real `action-locker` command on PATH, so the recording reads naturally
mkdir -p "$PLAY/bin"
cat > "$PLAY/bin/action-locker" <<'WRAPPER'
#!/usr/bin/env bash
exec python3 "$(dirname "$0")/../action_locker.py" "$@"
WRAPPER
chmod +x "$PLAY/bin/action-locker"

cd "$PLAY"

# Rewind: fresh unpinned ci.yml (the meta action-locker job is stripped —
# it can't resolve until the tool repo is public, and it's not the story)
cat > .github/workflows/ci.yml <<'YAML'
name: CI
on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test

  deploy:
    needs: [test]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
      - run: ./deploy.sh
YAML

cat > .github/workflows/release.yml <<'YAML'
name: Release
on:
  push:
    tags: ['v*']

jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
YAML

rm -f action-lock.json
rm -rf .github/vendored-actions

echo "Playground ready: $PLAY"
echo "Tip: export GITHUB_TOKEN (or \`gh auth login\`) before recording for clean output."

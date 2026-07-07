#!/usr/bin/env bash
# Build a scratch playground for recording the gifs/ tapes.
#
#   bash gifs/setup-playground.sh adopt       # rewound: mutable tags, no lockfile, no vendor
#   bash gifs/setup-playground.sh asis        # the demo repo exactly as committed
#   bash gifs/setup-playground.sh quarantine  # asis + lockfile policy floor of 9999 days
#                                             # (the steph-owl 0-day override stays,
#                                             #  so the gif shows precedence honestly)
#
# Expects the demo repo checked out as a sibling of this repo:
#   ../action-locker-demo
set -euo pipefail

MODE="${1:-adopt}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DEMO="${ROOT}/../action-locker-demo"
PLAY="/tmp/action-locker-playground"

[ -d "$DEMO" ] || { echo "error: expected demo repo at $DEMO" >&2; exit 1; }
case "$MODE" in adopt|asis|quarantine) ;; *) echo "error: mode must be adopt|asis|quarantine" >&2; exit 1;; esac

rm -rf "$PLAY"
cp -r "$DEMO" "$PLAY"
rm -rf "$PLAY/.git" "$PLAY/gifs"   # fresh history; no recording kit in the shot
cp "$ROOT/action_locker.py" "$PLAY/"

# A real `action-locker` command on PATH, so the recording reads naturally
mkdir -p "$PLAY/bin"
cat > "$PLAY/bin/action-locker" <<'WRAPPER'
#!/usr/bin/env bash
exec python3 "$(dirname "$0")/../action_locker.py" "$@"
WRAPPER
chmod +x "$PLAY/bin/action-locker"

cd "$PLAY"

if [ "$MODE" = "adopt" ]; then
  # Rewind to the "before" state: mutable tags, no lockfile, no vendor dir.
  # (The meta action-locker CI job is stripped — it isn't the adopt story.)
  cat > .github/workflows/ci.yml <<'YAML'
name: CI
on:
  pull_request:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm test

  deploy:
    needs: [test]
    runs-on: ubuntu-24.04
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
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - uses: softprops/action-gh-release@v2
        with:
          files: dist/*
YAML

  rm -f action-lock.json
  rm -rf .github/vendored-actions
fi

if [ "$MODE" = "quarantine" ]; then
  # An absurd global floor in the LOCKFILE (not the CLI — an explicit
  # --min-age-days would beat policy and steamroll the steph-owl override,
  # making the gif contradict itself).
  python3 - <<'PY'
import json
lock = json.load(open("action-lock.json"))
lock.setdefault("policy", {})["min_age_days"] = 9999
json.dump(lock, open("action-lock.json", "w"), indent=2, sort_keys=True)
open("action-lock.json", "a").write("\n")
PY
fi

git init -q -b main
git config user.name "Demo Dev"
git config user.email "dev@example.com"
git add -A
git commit -qm "baseline"

echo "Playground ready: $PLAY (mode: $MODE)"

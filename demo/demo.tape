# action-locker demo — regenerate the README gif with:
#
#   brew install vhs        # (or: go install github.com/charmbracelet/vhs@latest)
#   vhs demo/demo.tape      # run from the repo root
#
# Recording hits live GitHub (lock resolves refs, vendor downloads
# archives), so have GITHUB_TOKEN exported and expect the vendor step to
# take ~15s. Tune the Sleeps to taste.

Output demo/action-locker.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 12
Set TypingSpeed 30ms

Hide
Type "bash demo/setup-playground.sh && cd /tmp/action-locker-playground && export PATH=\"$PWD/bin:$PATH\" && clear"
Enter
Sleep 4s
Show

Type "# Your workflows trust mutable tags with your deploy credentials:"
Enter
Type "grep -n 'uses:' .github/workflows/ci.yml"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Type "# 1. Resolve every ref to an immutable commit SHA"
Enter
Type "action-locker lock"
Sleep 500ms
Enter
Sleep 6s

Type "# 2. Pin the workflow files (tag kept as a comment for Dependabot)"
Enter
Type "action-locker rewrite"
Sleep 500ms
Enter
Sleep 2s
Type "grep -n 'uses:' .github/workflows/ci.yml"
Enter
Sleep 3.5s

Type "clear"
Enter
Type "# 3. Vendor local snapshots — insurance against upstream deletion"
Enter
Type "action-locker vendor"
Sleep 500ms
Enter
Sleep 18s

Type "clear"
Enter
Type "# 4. The CI gate. Offline, no tokens, no excuses:"
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Type "# Now — someone tampers with a vendored action in a 'refactor' PR..."
Enter
Type "D=$(ls -d .github/vendored-actions/actions--checkout*)"
Enter
Type "echo '// definitely fine' >> \"$D/dist/index.js\""
Enter
Sleep 1s
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 4.5s

Type "# ...or quietly un-pins an action"
Enter
Type "sed -i.bak 's|actions/setup-node@[0-9a-f]*  # v4|actions/setup-node@v4|' .github/workflows/ci.yml"
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 4.5s

Type "clear"
Enter
Type "# pin everything. vendor critical.   github.com/Old-Well-Labs/action-locker"
Enter
Sleep 5s

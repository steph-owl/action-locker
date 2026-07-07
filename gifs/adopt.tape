# adopt.tape — the hero gif: pin an unpinned repo in three commands.
#   vhs gifs/adopt.tape   (from the repo root; ../action-locker-demo sibling
#   required; export GITHUB_TOKEN — lock resolves refs against live GitHub)
#
# NOTE: VHS strings have no escape sequences — keep shell lines free of
# double quotes, or wrap the Type argument in backticks.

Output gifs/adopt.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 680
Set Padding 12
Set TypingSpeed 30ms

Hide
Type "bash gifs/setup-playground.sh adopt && cd /tmp/action-locker-playground && export PATH=$PWD/bin:$PATH && clear"
Enter
Sleep 5s
Show

Type "# This repo trusts mutable tags — with its AWS deploy credentials:"
Enter
Type "grep -n 'uses:' .github/workflows/ci.yml"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Type "# 1. Resolve every tag to an immutable commit SHA."
Enter
Type "#    (too-fresh targets get held back to the newest aged release — automatically)"
Enter
Type "action-locker lock"
Sleep 500ms
Enter
Sleep 10s

Type "# 2. Pin the workflow files — tags kept as comments for Dependabot:"
Enter
Type "action-locker rewrite"
Sleep 500ms
Enter
Sleep 2s
Type "grep -n 'uses:' .github/workflows/ci.yml"
Enter
Sleep 3s

Type "# 3. The offline CI gate agrees:"
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 3.5s

Type "# Pinned. Locked. Verified.        github.com/steph-owl/action-locker"
Enter
Sleep 5s

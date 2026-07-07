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
Set Padding 20
Set TypingSpeed 25ms

Hide
Type "bash gifs/setup-playground.sh adopt && cd /tmp/action-locker-playground && export PATH=$PWD/bin:$PATH && clear"
Enter
Sleep 5s
Show

Type "# BEFORE ACTION LOCK: This repo trusts mutable tags — with its AWS deploy credentials:"
Enter
Type "grep -n 'uses:' .github/workflows/ci.yml"
Sleep 500ms
Enter
Sleep 4s

Type "clear"
Enter
Type "# 1.LOCK - Resolve every tag to an immutable commit SHA."
Enter
Type "#    (too-fresh targets get held back to the newest aged release — automatically)"
Enter
Type "action-locker lock"
Sleep 500ms
Enter
Type ""
Enter
Sleep 10s

Type "# 2. REWRITE Pin the workflow files — tags kept as comments for Dependabot:"
Enter
Type "action-locker rewrite"
Sleep 500ms
Enter
Sleep 2s
Type "grep -n 'uses:' .github/workflows/ci.yml"
Enter
Sleep 5s

Type "clear"
Enter
Type "# 3. VERIFY - CI agrees:"
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Type ""
Enter
Sleep 3.5s

Type "# Locked. Pinned Verified.        github.com/steph-owl/action-locker"
Enter
Type "# Old Well Labs is hiring! See readme! :D  -steph"
Enter
Sleep 4s

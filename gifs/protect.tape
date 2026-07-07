# protect.tape — vendored snapshots + integrity: tampering fails the build.
#   vhs gifs/protect.tape   (from the repo root; ../action-locker-demo
#   sibling required; fully OFFLINE — verify never touches the network)
#
# NOTE: VHS strings have no escape sequences — keep shell lines free of
# double quotes, or wrap the Type argument in backticks.

Output gifs/protect.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 680
Set Padding 12
Set TypingSpeed 30ms

Hide
Type "bash gifs/setup-playground.sh asis && cd /tmp/action-locker-playground && export PATH=$PWD/bin:$PATH && clear"
Enter
Sleep 4s
Show

Type "# This repo vendors its critical actions: local snapshots, content-hashed."
Enter
Type "ls .github/vendored-actions/"
Sleep 500ms
Enter
Sleep 2s
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Type "# A 'refactor' PR touches one vendored file..."
Enter
Type "D=$(ls -d .github/vendored-actions/actions--checkout*)"
Enter
Type "echo '// definitely fine' >> $D/dist/index.js"
Enter
Sleep 1s
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 4.5s

Type "# Restore the snapshot (or re-vendor) and you're green again:"
Enter
Type "git checkout -- ."
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 3s

Type "clear"
Enter
Type "# Un-pinning back to a mutable tag is caught the same way:"
Enter
Type "sed -i.bak 's|actions/setup-node@[0-9a-f]*  # v4|actions/setup-node@v4|' .github/workflows/ci.yml"
Enter
Type "action-locker verify"
Sleep 500ms
Enter
Sleep 4.5s

Type "# Content is identity. Lines can shift; hashes don't lie."
Enter
Type "#                                  github.com/steph-owl/action-locker"
Enter
Sleep 5s

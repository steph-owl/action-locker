# quarantine.tape — the age floor refusing what hasn't aged, the trust
# ladder naming its sources, and a policy override walking through the
# front door — for real: the floor lives in the lockfile policy, so the
# per-prefix override genuinely wins. (An explicit --min-age-days on the
# CLI would beat policy and refuse the override's repo too — that's
# documented precedence, and this gif must not contradict it.)
#
#   vhs gifs/quarantine.tape   (from the repo root; ../action-locker-demo
#   sibling required; export GITHUB_TOKEN — the ladder queries release,
#   PR, and commit dates against live GitHub)
#
# RECORD THIS ONE AFTER THE REPOS ARE PUBLIC: it re-resolves the demo's
# pinned steph-owl/action-locker ref, which needs the repo to exist.
#
# NOTE: VHS strings have no escape sequences — keep shell lines free of
# double quotes, or wrap the Type argument in backticks.

Output gifs/quarantine.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 12
Set TypingSpeed 30ms

Hide
Type "bash gifs/setup-playground.sh quarantine && cd /tmp/action-locker-playground && export PATH=$PWD/bin:$PATH && clear"
Enter
Sleep 4s
Show

Type "# This lockfile's policy sets an absurd 9999-day age floor — with one exception:"
Enter
Type "grep -A9 policy action-lock.json"
Sleep 500ms
Enter
Sleep 4s

Type "# Re-lock everything against that policy (hold-back off, to show refusals):"
Enter
Type "action-locker lock --force --no-fallback"
Sleep 500ms
Enter
Sleep 15s

Type "clear"
Enter
Type "# Three things worth noticing in that wall:"
Enter
Type "#  1. Every REFUSED names its trust-ladder rung — immutable release and"
Enter
Type "#     merged-PR dates are GitHub-server-attested; committer dates are not."
Enter
Type "#  2. The org's own repo walked through anyway: the most specific policy"
Enter
Type "#     override wins, and steph-owl/action-locker carries a 0-day floor."
Enter
Type "#  3. The hint tells you your options — this is quarantine, not breakage."
Enter
Sleep 6s

Type "# Fresh code can wait five days. Your deploy credentials can't be un-leaked."
Enter
Type "#                                        github.com/steph-owl/action-locker"
Enter
Sleep 5s

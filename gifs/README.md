# gifs/ — recording kit for the README gifs

(Not to be confused with [action-locker-demo](https://github.com/steph-owl/action-locker-demo),
the consumer example repo. This folder is just how the pictures get made.)

Each tape is one use case, ~30–45 seconds:

| Tape | Story | Needs |
|---|---|---|
| `adopt.tape` | Pin an unpinned repo in three commands (the hero gif) | network + `GITHUB_TOKEN` |
| `protect.tape` | Vendored-snapshot integrity: tamper → red, restore → green, un-pin → red | fully offline |
| `quarantine.tape` | A 9999-day floor set in lockfile *policy* refusing everything — except the org's own repo, whose per-prefix override genuinely wins | network + **public repos** (record last) |

(quarantine's floor deliberately lives in the playground's lockfile, not a
CLI flag: `--min-age-days` beats policy by documented precedence, which
would refuse the override's repo too and make the captions lie.)

## Recording

```bash
brew install vhs                       # pulls ttyd + ffmpeg
cd path/to/action-locker               # repo root; ../action-locker-demo must exist
export GITHUB_TOKEN=$(gh auth token)
vhs gifs/adopt.tape
vhs gifs/protect.tape
vhs gifs/quarantine.tape               # after the repos are public
```

Colors are automatic: VHS records a real TTY, so REFUSED comes out
yellow, errors red, and passes green — same as your terminal.

## Tips

- If output gets cut off mid-scene, bump that scene's `Sleep` (the lock
  and quarantine scenes make live API calls; timing varies).
- `adopt.tape` runs a plain `lock`: if an upstream tag is younger than
  the 5-day floor on recording day (looking at you, aws-actions), you'll
  see a live "held back to vX.Y.Z" note — that's the feature demoing
  itself; leave it in the take. `quarantine.tape` uses `--no-fallback`
  so the refusal path stays visible (and the wall stays fast).
- Keep gifs under ~10MB or GitHub renders them sluggishly — drop
  `Set FontSize`/`Width` a notch if needed.
- VHS strings have no escape sequences: no `\"` inside `Type "..."` —
  use quote-free shell or backtick-delimited strings.

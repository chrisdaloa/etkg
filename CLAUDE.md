# Fork version

`FORK_VERSION` (repo root) is a plain integer build counter for this fork
(`chrisdaloa/etkg`), shown in the web dashboard next to the upstream
version (`main.py`'s `VERSION`, which drives the update-check logic and
must not be touched for this purpose).

**Before every `git push` to the `myfork` remote**, increment `FORK_VERSION`
by 1 and include it in the push (either in the same commit being pushed, or
as a small separate commit). Do not bump it for pushes to `origin`
(upstream) or for commits that are not being pushed to `myfork`.

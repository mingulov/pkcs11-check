# Running under a tracer / profiler / observer

When pkcs11-check itself is the workload under an external observer
(`strace`, `perf`, an eBPF call profiler), run it the way it is meant
to be run and let the observer follow the process tree. Do not reshape
the run to fit the observer.

## Processes, not one PID

The default (`--isolation auto`) runs each test unit in a fresh
`python -m pytest` subprocess. Short-lived helper subprocesses also
load the module, for collection and the capability probe. See
`docs/file-isolation.md` for the runner design.

A tool that attaches by PID therefore only sees the runner. Use the
tool's follow-children or system-wide mode instead (`strace -f`,
`perf record -a`, eBPF system scope).

## Do not switch to `--isolation none` for this

`--isolation none` runs everything in one process, which looks
convenient for PID attachment, but it is not crash-safe: a provider
crash kills the whole run instead of being recorded as one unit's
result.

If a single process is really required, use `--isolation none` only
with a selection that does not crash the provider, and treat a
provider crash as ending that run (record it), never as a reason to
drop tests.

## Crashes are recorded results

A provider crash is a recorded result, not a suite failure to work
around. Under the default isolation the crashing unit is recorded
and the run continues; deleting crashing tests with `-k` exclusions
hides provider defects instead of measuring them.

`disabled-tests` files exist for known hangs/crashes you deliberately
exclude up front (documented, reviewable), not as a crash workaround
discovered mid-run.

## Run durations

Plan by profile, slowest first. Rough magnitudes on the SoftHSM
reference module (container, shared host): the smoke selection takes
a couple of minutes, the fast profile (`--skip-slow`) several
minutes, and a full run tens of minutes. Other providers differ
considerably; HSM-class modules can take several times longer.

To time your own setup, run each profile once with `time` and the
exact selection you intend to keep; provider, machine, and vector
inventory dominate the result, so do not extrapolate these rough
magnitudes across setups.

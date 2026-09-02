# Releasing

Releases are cut by dispatching the **Release** workflow (`.github/workflows/publish.yml`) from the Actions tab. The workflow does everything: it verifies the repository state, builds, tags, uploads to PyPI, and publishes the GitHub Release.

## Rehearsing on TestPyPI

Dispatch the manual **TestPyPI** workflow (`.github/workflows/publish-testpypi.yml`) from `main` with the package version. Leave `dry_run` ticked first to verify and build without uploading, then dispatch it again with `dry_run` unticked to publish the wheel and sdist to TestPyPI. This workflow never creates a tag or GitHub Release and never publishes to production PyPI.

TestPyPI is a separate service and needs one-time setup before the first upload:

1. Create the GitHub environment `testpypi`, restrict it to `main`, and optionally require approval.
2. In the TestPyPI account's **Publishing** settings, add a pending GitHub publisher for project `pkcs11-check`, owner `mingulov`, repository `pkcs11-check`, workflow `publish-testpypi.yml`, and environment `testpypi`.

The first successful upload creates the TestPyPI project and converts the pending publisher into the project's normal publisher. Files cannot be overwritten while they exist, so every repeat or changed rehearsal needs a new version; the workflow fails loudly if the version is already present. Unlike production PyPI, TestPyPI is not permanent and may periodically prune projects or accounts.

## Cutting a release

1. On `main`, bump `__version__` in `src/pkcs11_check/__init__.py` and fold the development branch's `## Unreleased` notes into a matching `## [X.Y.Z] - YYYY-MM-DD` section in `CHANGELOG.md`. These are one atomic edit: the top numbered changelog heading must match the package version at release time.
2. Run `uv lock` if dependencies changed, and check the whole gate set locally.
3. Push to `main` and wait for CI to go green. The release refuses to run otherwise.
4. Dispatch **Release** with the version and `dry_run` left ticked. Read the job summary: it prints the commit, the tag it would create, and the exact release notes.
5. Dispatch again with `dry_run` unticked.

`uvx hatch version X.Y.Z` will write the version for you. `uv version` does NOT work on this project: the version is dynamic, and uv refuses to read or write dynamic versions.

## What the workflow refuses to do

- Release from any ref other than `main`.
- Release a commit whose CI is not green, or which has no CI run at all.
- Release when `pyproject.toml` loses `dynamic = ["version"]` or gains a static `[project].version` (the version comes only from `src/pkcs11_check/__init__.py`), when the top `CHANGELOG.md` entry does not match that version, or when the new version is not greater than the previous changelog entry.
- Release when `uv.lock` is stale.
- Release when the tag already exists on a different commit.

The same version checks run on every push through `tests/test_release_hygiene.py::test_version_is_consistent_across_release_files`, so drift normally surfaces long before release day.

## If a release half-finishes

The jobs are ordered `verify -> build -> tag -> publish -> github-release`, so the tag exists before anything irreversible happens: that ordering makes "on PyPI but recorded nowhere" impossible, which is exactly how 0.1.8 went out. It also means both partial states below are safe to repeat: the tag guard accepts a tag that already points at this commit, so recreating it is a no-op, and the PyPI upload uses `skip-existing`, so repeating it skips the duplicate instead of failing on it.

The recovery path that actually works is **"Re-run failed jobs"** on the original workflow run, from the run's page in the Actions tab, not a fresh dispatch. Artifacts are scoped to the run, so the `distributions` and `release-notes` artifacts built by the first attempt are still there for the jobs that need them, and because `verify` and `build` already succeeded they are not re-executed, so the original inputs (the requested version, the commit, `dry_run`) stay exactly what they were the first time.

- **Tag pushed, PyPI upload failed.** Re-run failed jobs resumes at `publish`, using the `distributions` artifact from the first attempt and the tag that is already in place.
- **PyPI uploaded, GitHub Release failed.** Re-run failed jobs resumes at `github-release`; the earlier `publish` already used `skip-existing`, so even a repeated `publish` would be harmless.

Re-dispatching **Release** from the Actions tab works too, but only as a fallback, and only while `main` still points at the commit that was released. If `main` has moved on, for example an unrelated PR merged after the tag was pushed, a re-dispatch runs against that new commit, the tag guard sees the tag pointing somewhere else, and the run hard-fails with no way forward: `workflow_dispatch` cannot target a bare SHA, so there is no way to aim a fresh dispatch back at the commit the tag actually points at. Re-run failed jobs does not have this problem, because it always resumes the original run against the original commit.

The operational rule this implies: do not push to `main` while a release run is in flight. A merge landing between the tag push and a resume is the one thing that turns a recoverable half-finished release into one that needs manual intervention.

A PyPI upload can never be replaced, only yanked. That is why `dry_run` defaults to true.

## The workflow filename is load-bearing

PyPI Trusted Publishing binds to the filename of the dispatched workflow, and PyPI does not support a reusable workflow as the registered publisher. The file is therefore still called `publish.yml` even though it now does far more than publish. Renaming it breaks publishing until a matching publisher entry is added at https://pypi.org/manage/project/pkcs11-check/settings/publishing/.

# OpenCryptoki Custom Source Support Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Modify the OpenCryptoki master Dockerfile and docker-compose configuration to allow building from a custom branch or Pull Request head.

**Architecture:** Use Docker `ARG`s with environment variable defaults in `docker-compose.test.yml`. A conditional `RUN` block in `Dockerfile.master` will handle fetching either a branch (default) or a specific PR.

**Tech Stack:** Docker, Git, Shell.

---

### Task 1: Update Dockerfile.master

**Files:**
- Modify: `docker/opencryptoki/Dockerfile.master:28-30`

**Step 1: Replace hardcoded git clone with parameterized logic**

Replace:
```dockerfile
29: RUN git clone --depth 1 https://github.com/opencryptoki/opencryptoki.git /build/opencryptoki
30: WORKDIR /build/opencryptoki
```

With:
```dockerfile
ARG OPENCRYPTOKI_REPO=https://github.com/opencryptoki/opencryptoki.git
ARG OPENCRYPTOKI_BRANCH=master
ARG OPENCRYPTOKI_PR=""

RUN if [ -n "${OPENCRYPTOKI_PR}" ]; then \
        git clone --depth 1 ${OPENCRYPTOKI_REPO} /build/opencryptoki && \
        cd /build/opencryptoki && \
        git fetch --depth 1 origin pull/${OPENCRYPTOKI_PR}/head && \
        git checkout FETCH_HEAD; \
    else \
        git clone --depth 1 --branch ${OPENCRYPTOKI_BRANCH} ${OPENCRYPTOKI_REPO} /build/opencryptoki; \
    fi
WORKDIR /build/opencryptoki
```

**Step 2: Commit changes**

```bash
git add docker/opencryptoki/Dockerfile.master
git commit -m "docker: allow custom branch/PR in opencryptoki-master"
```

### Task 2: Update docker-compose.test.yml

**Files:**
- Modify: `docker/docker-compose.test.yml:92-94`

**Step 1: Add parameterized build args for test-opencryptoki-master**

Modify the `args` section for `test-opencryptoki-master` to include the new arguments with environment variable defaults for easy host-side overriding.

```yaml
      args:
        OPENSSL_VERSION: "${OPENSSL_VERSION:-3.6.1}"
        OPENCRYPTOKI_REPO: "${OPENCRYPTOKI_REPO:-https://github.com/opencryptoki/opencryptoki.git}"
        OPENCRYPTOKI_BRANCH: "${OPENCRYPTOKI_BRANCH:-master}"
        OPENCRYPTOKI_PR: "${OPENCRYPTOKI_PR:-}"
```

**Step 2: Commit changes**

```bash
git add docker/docker-compose.test.yml
git commit -m "docker: expose opencryptoki build args in compose"
```

### Task 3: Build Verification (PR 929)

**Step 1: Trigger a build for PR 929**

Run:
```bash
OPENCRYPTOKI_PR=929 docker compose -f docker/docker-compose.test.yml build test-opencryptoki-master
```

**Expected Outcome:** Docker builds successfully, fetching PR 929 head.

**Step 2: Verify the version inside the container**

Run:
```bash
OPENCRYPTOKI_PR=929 docker compose -f docker/docker-compose.test.yml run --rm test-opencryptoki-master cat /tmp/oc_version.txt
```

**Note:** If PR 929 changed the version string in `configure.ac`, it should be reflected here.

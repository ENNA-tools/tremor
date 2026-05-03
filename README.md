# tremor

Pipeline behavioral anomaly detection for GitHub Actions.

You audit your code. Who audits your pipeline?

## Four modes

### `audit` — Static workflow analysis

Scans workflow YAML files for supply chain attack vectors:

| Check | ID | What it catches |
|---|---|---|
| Unpinned Actions | T001 | Action refs using tags/branches instead of commit SHAs |
| Mutable Tags | T002 | Major-version tags (v4) that maintainers can silently re-point |
| Dangerous Triggers | T003 | pull_request_target, workflow_run, issue_comment abuse vectors |
| Script Injection | T004 | Untrusted context (${{ github.event.* }}) interpolated into shell |
| Excessive Permissions | T005 | Overly broad GITHUB_TOKEN scopes |
| Secret Exposure | T006 | Secrets interpolated directly in run blocks instead of env vars |
| Untrusted PR Checkout | T007 | pull_request_target checking out fork PR head (credential theft) |

### `diff` — PR trust surface analysis

Compares workflow files between branches and reports security-relevant changes:

- New action references or version downgrades (SHA → mutable tag)
- Permission escalations or removed permission blocks
- New dangerous triggers or removed trigger guards
- New secret references
- Removed environment protections
- Modified run blocks

Posts a formatted report as a PR comment with risk delta scoring.

### `monitor` — Runtime behavioral baselining

Snapshots the pipeline execution environment and compares against a rolling baseline:

| Check | ID | What it catches |
|---|---|---|
| New Network Host | T101 | Outbound connections to hosts not in baseline |
| Suspicious Process | T102 | Processes not in baseline's known process list |
| New Secret Variable | T103 | New secret-pattern env vars not in baseline |
| Timing Anomaly | T104 | Step duration z-score exceeds threshold (planned) |

First run creates the baseline. Subsequent runs compare and flag deviations.

### `epicenter` — Build artifact anomaly scanning

Scans build output directories for steganographic content, hidden payloads, obfuscated commands, and supply chain attack indicators embedded in artifacts.

| Finding type | What it catches |
|---|---|
| Steganographic content | Data hidden in image LSBs, trailing bytes after EOF markers, appended archives |
| Obfuscated payloads | Base64-encoded shell commands, hex-encoded executables, polyglot files |
| Hidden commands | Executable content disguised as data files, shebang lines in non-script extensions |
| Supply chain indicators | Unexpected network URLs in artifacts, cryptocurrency addresses, encoded C2 patterns |
| Entropy anomalies | File regions with entropy inconsistent with declared content type |

Epicenter assigns an overall anomaly score (0-100). If the score meets or exceeds the configured threshold, the step exits with code 2.

```yaml
- uses: 1oosedows/tremor@main
  with:
    mode: epicenter
    target: dist/
    threshold: '25'
```

## Usage

```yaml
# Audit mode — scan workflow files on every PR
- uses: 1oosedows/tremor@main
  with:
    mode: audit
    severity-threshold: medium

# Diff mode — analyze trust surface changes when workflows are modified
- uses: 1oosedows/tremor@main
  with:
    mode: diff
    base-ref: origin/main

# Monitor mode — runtime behavioral baseline during deploys
- uses: 1oosedows/tremor@main
  with:
    mode: monitor
    severity-threshold: high

# Epicenter mode — scan build artifacts for hidden threats
- uses: 1oosedows/tremor@main
  with:
    mode: epicenter
    target: dist/
    threshold: '25'
```

See `examples/` for full workflow files.

## Configuration

Create `.tremor/config.yml` in your repo:

```yaml
checks:
  unpinned_actions: true
  dangerous_triggers: true
  script_injection: true
  excessive_permissions: true
  secret_exposure: true
  mutable_tags: true
  untrusted_pr_checkout: true

allow:
  actions:
    - actions/checkout
  permissions: []
  triggers: []
```

## Local usage

```bash
pip install pyyaml
cd src && TREMOR_MODE=audit python main.py

# Epicenter mode locally
cd src && TREMOR_MODE=epicenter TREMOR_TARGET=../dist python main.py
```

## License

MIT

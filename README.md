# tremor

Pipeline behavioral anomaly detection for GitHub Actions.

You audit your code. Who audits your pipeline?

## What it does

Tremor scans your GitHub Actions workflows for supply chain attack vectors that static analysis misses:

| Check | ID | What it catches |
|---|---|---|
| Unpinned Actions | T001 | Action refs using tags/branches instead of commit SHAs |
| Mutable Tags | T002 | Major-version tags (v4) that maintainers can silently re-point |
| Dangerous Triggers | T003 | pull_request_target, workflow_run, issue_comment abuse vectors |
| Script Injection | T004 | Untrusted context (${{ github.event.* }}) interpolated into shell |
| Excessive Permissions | T005 | Overly broad GITHUB_TOKEN scopes |
| Secret Exposure | T006 | Secrets interpolated directly in run blocks instead of env vars |
| Untrusted PR Checkout | T007 | pull_request_target checking out fork PR head (credential theft) |

## Usage

```yaml
- uses: 1oosedows/tremor@main
  with:
    mode: audit
    severity-threshold: medium
```

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
cd src && python main.py
```

## License

MIT

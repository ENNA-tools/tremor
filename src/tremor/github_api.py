"""GitHub API client for workflow analysis and PR reporting."""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from pathlib import Path


class GitHubAPIError(Exception):
    def __init__(self, status: int, url: str, body: str):
        self.status = status
        self.url = url
        self.body = body
        super().__init__(f"GitHub API {status} on {url}: {body}")


class GitHubClient:
    def __init__(self) -> None:
        self.token = os.environ.get("GITHUB_TOKEN")
        self.repository = os.environ.get("GITHUB_REPOSITORY")
        self.api_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")

        if not self.token:
            raise RuntimeError("GITHUB_TOKEN environment variable is not set")
        if not self.repository:
            raise RuntimeError("GITHUB_REPOSITORY environment variable is not set")

        self.api_url = self.api_url.rstrip("/")

    def _request(
        self, method: str, path: str, body: dict | None = None
    ) -> dict | list:
        url = f"{self.api_url}{path}"
        data = json.dumps(body).encode() if body else None

        req = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        if data:
            req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            response_body = e.read().decode(errors="replace")
            raise GitHubAPIError(e.code, url, response_body) from None

    def get_workflow_runs(
        self, workflow_id: str | int, count: int = 20
    ) -> list[dict]:
        path = (
            f"/repos/{self.repository}/actions/workflows/{workflow_id}/runs"
            f"?status=success&per_page={count}"
        )
        data = self._request("GET", path)
        return data["workflow_runs"][:count]

    def get_run_timing(self, run_id: int) -> dict:
        path = f"/repos/{self.repository}/actions/runs/{run_id}/timing"
        return self._request("GET", path)

    def get_run_jobs(self, run_id: int) -> list[dict]:
        path = f"/repos/{self.repository}/actions/runs/{run_id}/jobs"
        data = self._request("GET", path)
        return data["jobs"]

    def find_existing_comment(
        self, pr_number: int, marker: str = "<!-- tremor-report -->"
    ) -> int | None:
        page = 1
        while True:
            path = (
                f"/repos/{self.repository}/issues/{pr_number}/comments"
                f"?per_page=100&page={page}"
            )
            comments = self._request("GET", path)
            if not comments:
                return None
            for comment in comments:
                if marker in comment.get("body", ""):
                    return comment["id"]
            if len(comments) < 100:
                return None
            page += 1

    def post_or_update_comment(
        self,
        pr_number: int,
        body: str,
        marker: str = "<!-- tremor-report -->",
    ) -> None:
        full_body = f"{marker}\n{body}"
        existing_id = self.find_existing_comment(pr_number, marker)

        if existing_id:
            path = f"/repos/{self.repository}/issues/comments/{existing_id}"
            self._request("PATCH", path, {"body": full_body})
        else:
            path = f"/repos/{self.repository}/issues/{pr_number}/comments"
            self._request("POST", path, {"body": full_body})

    def write_step_summary(self, content: str) -> None:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return
        with open(summary_path, "a") as f:
            f.write(content)
            if not content.endswith("\n"):
                f.write("\n")


def get_pr_number() -> int | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path or not Path(event_path).is_file():
        return None

    try:
        with open(event_path) as f:
            event = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    pr = event.get("pull_request")
    if pr and isinstance(pr.get("number"), int):
        return pr["number"]

    # Fallback: some events store it at top level (issue_comment on PRs)
    number = event.get("number")
    if isinstance(number, int):
        return number

    return None

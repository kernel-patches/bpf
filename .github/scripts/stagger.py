#!/usr/bin/env python3
"""Stagger CI runs during KPD rebase storms.

When KPD rebases all PR branches after an upstream commit, hundreds of
workflow runs fire at once.  This script detects the storm and sleeps
for a random delay to spread the load.

Storm = all of:
  1. PR synchronize event (force-push rebase, not a new PR)
  2. Base branch updated within the last 30 minutes (KPD just mirrored)
  3. More than 5 active workflow runs (queued + in-progress)
  4. Active runs >= 20% of open PRs

If detected, sleeps a random 1-10 minutes then proceeds.
cancel-in-progress on the concurrency group kills sleeping runs on new pushes.
"""

import os
import random
import time
from datetime import datetime, timezone

import requests

BASE_BRANCH_RECENCY_S = 1800  # base branch "just updated" threshold
STORM_RATIO = 0.2  # active runs / open PRs threshold
STORM_MIN_ACTIVE = 5  # minimum active runs to consider a storm
WAIT_MIN_S = 60  # min delay
WAIT_MAX_S = 600  # max delay


def gh_api(endpoint):
    token = os.environ.get("GITHUB_TOKEN", "")
    resp = requests.get(
        f"https://api.github.com{endpoint}",
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
        },
    )
    resp.raise_for_status()
    return resp.json()


def base_branch_age_s(repo, base_branch):
    """Seconds since last commit on the base branch, or None on error."""
    try:
        sha = gh_api(f"/repos/{repo}/branches/{base_branch}")["commit"]["sha"]
        date_str = gh_api(f"/repos/{repo}/commits/{sha}")["commit"]["committer"]["date"]
        commit_time = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - commit_time).total_seconds()
    except Exception as e:
        print(f"Warning: could not get base branch age: {e}")
        return None


def active_run_count(repo):
    """Number of queued + in-progress workflow runs."""
    total = 0
    for status in ("queued", "in_progress"):
        try:
            data = gh_api(f"/repos/{repo}/actions/runs?status={status}&per_page=1")
            total += data.get("total_count", 0)
        except Exception as e:
            print(f"Warning: could not query {status} runs: {e}")
    return total


def open_pr_count(repo):
    """Number of open pull requests."""
    try:
        data = gh_api(f"/search/issues?q=repo:{repo}+type:pr+state:open&per_page=1")
        return data.get("total_count", 0)
    except Exception as e:
        print(f"Warning: could not query open PRs: {e}")
        return 0


def main():
    action = os.environ.get("GITHUB_EVENT_ACTION", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    base = os.environ.get("PR_BASE_BRANCH", "")

    if action != "synchronize":
        return

    if not repo or not base:
        return

    age = base_branch_age_s(repo, base)
    if age is None or age > BASE_BRANCH_RECENCY_S:
        print(f"Base branch {base} updated {age}s ago — no storm.")
        return

    active = active_run_count(repo)
    if active <= STORM_MIN_ACTIVE:
        print(f"Only {active} active runs — no storm.")
        return

    open_prs = open_pr_count(repo)
    if open_prs == 0:
        return

    ratio = active / open_prs
    if ratio < STORM_RATIO:
        print(f"{active} active / {open_prs} PRs ({ratio:.0%}) — no storm.")
        return

    delay = random.randint(WAIT_MIN_S, WAIT_MAX_S)
    print(
        f"Storm detected: base {base} updated {age:.0f}s ago, "
        f"{active} active / {open_prs} PRs ({ratio:.0%}). "
        f"Waiting {delay}s."
    )
    time.sleep(delay)
    print("Proceeding.")


if __name__ == "__main__":
    main()

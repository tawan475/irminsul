#!/usr/bin/env python3
"""Open an issue when Dimbreath publishes game data no release carries yet.

Irminsul's release builds download Dimbreath's newest game data dump
(gitlab.com/Dimbreath/animegamedata2, through the `anime-game-data` crate in
build.rs) when they are built. A release published after a dump commit
therefore already carries it, and a dump newer than the latest release is new
characters, weapons, artifacts and materials waiting for a release to ship.

.github/workflows/game-data-watch.yml runs this once a day. It reads the
newest dump commit, the latest release's publish date and the issues labelled
`game-data`, and opens one issue per dump that no release carries yet.

The dump commit comes from git, as it does for the crate: a shallow clone of
the repository that fetches the newest commit object and nothing else.
gitlab.com's REST API, which this used to read, intermittently answers with a
Cloudflare bot check (an HTTP 403 HTML page); it is still asked when git cannot
answer.

Usage: python .github/scripts/game_data_watch.py [--dry-run]
  GITHUB_TOKEN needs issues: write and contents: read. GITHUB_REPOSITORY
  defaults to tawan475/irminsul. --dry-run prints the decision and writes
  nothing.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

DUMP_REPO_URL = "https://gitlab.com/Dimbreath/animegamedata2"
DUMP_GIT_URL = f"{DUMP_REPO_URL}.git"
# The fallback when git cannot answer.
DUMP_COMMITS_URL = "https://gitlab.com/api/v4/projects/83871005/repository/commits?per_page=1"

# What `git log` prints for the dump commit: sha, committer date (strict ISO
# 8601) and subject, NUL-separated (a subject can hold anything but a NUL).
LOG_FORMAT = "%H%x00%cI%x00%s"
GIT_TIMEOUT_S = 120
GITHUB_API = "https://api.github.com"
DEFAULT_REPO = "tawan475/irminsul"

LABEL = "game-data"
LABEL_COLOR = "1d76db"
LABEL_DESCRIPTION = "Game data newer than the latest release"

# A dump commit's title, e.g. `CNRELWin7.1.0_R48379043_S48511369_D48533839`:
# the client build and game version, then `_R`, `_S` and `_D` revision
# numbers. The `D` one (with the version) names the issue.
DUMP_TITLE = re.compile(r"(?P<label>[A-Za-z]+(?P<version>\d+\.\d+\.\d+))(?:_[A-Z]+\d+)*")
DATA_REVISION = re.compile(r"_(D\d+)(?=_|$)")

USER_AGENT = "irminsul-game-data-watch"


def parse_time(text: str) -> datetime:
    """An ISO 8601 time from either API, as an aware datetime."""
    value = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Dump:
    """The newest commit of Dimbreath's dump."""

    sha: str
    title: str
    committed_at: datetime
    url: str

    @property
    def short_sha(self) -> str:
        return self.sha[:8]


@dataclass(frozen=True)
class DumpName:
    """What a well-formed dump title says."""

    label: str  # `CNRELWin7.1.0`
    version: str  # `7.1.0`
    data_revision: str | None  # `D48533839`


def parse_dump_title(title: str) -> DumpName | None:
    """The build, game version and data revision a dump title names, or None
    when the title is not in the usual shape."""
    title = title.strip()
    match = DUMP_TITLE.fullmatch(title)
    if not match:
        return None
    revision = DATA_REVISION.search(title)
    return DumpName(match["label"], match["version"], revision[1] if revision else None)


@dataclass(frozen=True)
class Release:
    tag: str
    published_at: datetime


@dataclass(frozen=True)
class Issue:
    number: int
    title: str
    body: str


@dataclass(frozen=True)
class Decision:
    open_issue: bool
    reason: str
    title: str | None = None
    body: str | None = None


def issue_title(dump: Dump) -> str:
    name = parse_dump_title(dump.title)
    if name is None:
        # Not the usual shape: say what the commit said, and which commit.
        return f"Game data {dump.title.strip() or 'dump'} ({dump.short_sha}) available"
    return f"Game data {name.label} ({name.data_revision or dump.short_sha}) available"


def issue_body(dump: Dump, release: Release | None) -> str:
    name = parse_dump_title(dump.title)
    version = name.version if name else "unknown (the commit title is not in the usual shape)"
    if release is None:
        latest = "there is no release yet"
    else:
        latest = f"the latest release, {release.tag}, was published {release.published_at.isoformat()}"
    return "\n".join(
        [
            "Dimbreath published a game data dump that no Irminsul release carries yet:",
            f"{latest}.",
            "",
            f"- Game version: {version}",
            f"- Dump: `{dump.title.strip()}`",
            f"- Commit: `{dump.sha}`",
            f"- Committed: {dump.committed_at.isoformat()}",
            f"- Link: {dump.url}",
            "",
            "Release builds download the newest dump when they are built, so shipping",
            "it takes a release, not a code change:",
            "",
            "1. Run **Create Release** on `main` (Actions → Create Release → Run workflow)",
            "   to ship it.",
            "2. Check the export after the patch with a real login. If something is",
            "   missing, record a login with a debug build and replay it with",
            "   `--replay-export` (README, \"Game patches\").",
            "",
            "Opened by `.github/workflows/game-data-watch.yml`, once per dump.",
        ]
    )


def reported_in(dump: Dump, issues: list[Issue]) -> Issue | None:
    """The issue already filed for this dump, open or closed, if any."""
    title = issue_title(dump)
    for issue in issues:
        if issue.title == title or dump.short_sha in issue.title or dump.sha in issue.body:
            return issue
    return None


def decide(dump: Dump, release: Release | None, issues: list[Issue]) -> Decision:
    """Whether this dump needs an issue opened."""
    if release is not None and dump.committed_at <= release.published_at:
        return Decision(
            False,
            f"{release.tag} (published {release.published_at.isoformat()}) was built after "
            f"dump {dump.short_sha} (committed {dump.committed_at.isoformat()})",
        )
    existing = reported_in(dump, issues)
    if existing is not None:
        return Decision(False, f"dump {dump.short_sha} is already reported in #{existing.number}")
    newer_than = release.tag if release else "every release (there are none)"
    return Decision(
        True,
        f"dump {dump.short_sha} is newer than {newer_than}",
        issue_title(dump),
        issue_body(dump, release),
    )


# --- git -----------------------------------------------------------------------

# `run_git`'s signature: (args) -> stdout; raises RuntimeError on failure.
Git = Callable[[list], str]


def run_git(args: list) -> str:
    """`git <args>`'s standard output. Raises RuntimeError when git is missing,
    fails or takes longer than GIT_TIMEOUT_S."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        result = subprocess.run(
            ["git", *args], capture_output=True, text=True, timeout=GIT_TIMEOUT_S, env=env
        )
    except FileNotFoundError as error:
        raise RuntimeError("git is not installed") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"git {' '.join(args)} took longer than {GIT_TIMEOUT_S} s") from error
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def parse_log(output: str) -> tuple[str, datetime, str]:
    """(sha, committed at, title) from `git log -1 --format=LOG_FORMAT`."""
    fields = output.rstrip("\r\n").split("\0")
    if len(fields) != 3 or not re.fullmatch(r"[0-9a-fA-F]{40}(?:[0-9a-fA-F]{24})?", fields[0]):
        raise RuntimeError(f"unexpected git log output: {output[:200]!r}")
    sha, committed, title = fields
    try:
        committed_at = parse_time(committed)
    except ValueError as error:
        raise RuntimeError(f"unexpected commit date in git log output: {committed!r}") from error
    return sha.lower(), committed_at, title


def newest_dump_from_git(git: Git = run_git) -> Dump:
    """The dump's newest commit, from a shallow, tree-less clone: one commit
    object, about a kilobyte, whatever the size of the dump."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        repo = os.path.join(tmp, "dump.git")
        git(["clone", "--quiet", "--bare", "--depth", "1", "--filter=tree:0", DUMP_GIT_URL, repo])
        sha, committed_at, title = parse_log(git(["--git-dir", repo, "log", "-1", f"--format={LOG_FORMAT}"]))
    return Dump(sha=sha, title=title, committed_at=committed_at, url=f"{DUMP_REPO_URL}/-/commit/{sha}")


# --- the two APIs ---------------------------------------------------------------

# `http_request`'s signature: (method, url, token, payload) -> (status, body).
Request = Callable[..., tuple]


def http_request(method: str, url: str, token: str = "", payload: object = None) -> tuple[int, object]:
    """One JSON request. Returns (status, parsed body); a 404 is returned rather
    than raised, every other HTTP error raises."""
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    if url.startswith(GITHUB_API):
        headers["Accept"] = "application/vnd.github+json"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
        if token:
            headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            content_type = response.headers.get("Content-Type")
            status = response.status
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return 404, None
        raw = error.read()
        if looks_like_html(error.headers.get("Content-Type") if error.headers else None, raw):
            raise RuntimeError(f"{method} {url} failed with {error.code}: {html_kind(raw)} instead of JSON") from error
        detail = raw.decode(errors="replace")[:500]
        raise RuntimeError(f"{method} {url} failed with {error.code}: {detail}") from error
    if looks_like_html(content_type, raw):
        raise RuntimeError(f"{method} {url} answered {status} with {html_kind(raw)} instead of JSON")
    return status, json.loads(raw) if raw else None


def looks_like_html(content_type: str | None, raw: bytes) -> bool:
    """An HTML page where JSON was asked for: how gitlab.com's Cloudflare front
    answers a request it wants a browser for ("Just a moment...")."""
    return "text/html" in (content_type or "").lower() or raw.lstrip()[:1] == b"<"


def html_kind(raw: bytes) -> str:
    if b"Just a moment" in raw or b"challenge-platform" in raw:
        return "a Cloudflare bot check page"
    return "an HTML page"


class Api:
    """Dimbreath's newest dump commit and this repository's GitHub releases and
    issues. `request` is `http_request` and `git` is `run_git`, or stubs in the
    tests."""

    def __init__(self, repo: str, token: str = "", request: Request = http_request, git: Git = run_git):
        self.repo = repo
        self.token = token
        self._request = request
        self._git = git

    def _get(self, url: str) -> object:
        status, data = self._request("GET", url, self.token)
        if status == 404:
            raise RuntimeError(f"GET {url}: not found")
        return data

    def _github(self, path: str) -> str:
        return f"{GITHUB_API}/repos/{self.repo}{path}"

    def newest_dump(self) -> Dump:
        """From git; from the GitLab API only when git cannot answer."""
        try:
            return newest_dump_from_git(self._git)
        except RuntimeError as git_error:
            print(f"git could not read the dump ({git_error}); asking the GitLab API")
            try:
                return self.newest_dump_from_api()
            except RuntimeError as api_error:
                raise RuntimeError(
                    f"unable to read the newest dump commit: git: {git_error}; GitLab API: {api_error}"
                ) from api_error

    def newest_dump_from_api(self) -> Dump:
        commits = self._get(DUMP_COMMITS_URL)
        if not isinstance(commits, list) or not commits:
            raise RuntimeError(f"GitLab returned no commits for the dump: {commits!r}")
        commit = commits[0]
        sha = commit["id"]
        return Dump(
            sha=sha,
            title=commit.get("title") or "",
            committed_at=parse_time(commit.get("committed_date") or commit["created_at"]),
            url=commit.get("web_url") or f"{DUMP_REPO_URL}/-/commit/{sha}",
        )

    def latest_release(self) -> Release | None:
        """The most recently published release. Pre-releases count: they are
        built the same way, so they carry the dump just the same."""
        releases = self._get(self._github("/releases?per_page=30"))
        published = [
            Release(release["tag_name"], parse_time(release["published_at"]))
            for release in releases or []
            if not release.get("draft") and release.get("published_at")
        ]
        return max(published, key=lambda release: release.published_at, default=None)

    def labelled_issues(self) -> list[Issue]:
        """Every issue labelled `game-data`, open or closed."""
        issues: list[Issue] = []
        for page in range(1, 11):
            batch = self._get(self._github(f"/issues?labels={LABEL}&state=all&per_page=100&page={page}"))
            for item in batch or []:
                if "pull_request" in item:
                    continue
                issues.append(Issue(item["number"], item.get("title") or "", item.get("body") or ""))
            if len(batch or []) < 100:
                break
        return issues

    def ensure_label(self) -> None:
        status, _ = self._request("GET", self._github(f"/labels/{LABEL}"), self.token)
        if status == 404:
            self._request(
                "POST",
                self._github("/labels"),
                self.token,
                {"name": LABEL, "color": LABEL_COLOR, "description": LABEL_DESCRIPTION},
            )

    def create_issue(self, title: str, body: str) -> str:
        _, issue = self._request(
            "POST", self._github("/issues"), self.token, {"title": title, "body": body, "labels": [LABEL]}
        )
        return issue["html_url"] if isinstance(issue, dict) else ""


def run(api: Api, dry_run: bool = False) -> Decision:
    dump = api.newest_dump()
    release = api.latest_release()
    print(f"newest dump: {dump.title.strip()} ({dump.sha}, committed {dump.committed_at.isoformat()})")
    if release:
        print(f"latest release: {release.tag} (published {release.published_at.isoformat()})")
    else:
        print("latest release: none")

    decision = decide(dump, release, api.labelled_issues())
    print(("open an issue: " if decision.open_issue else "nothing to do: ") + decision.reason)
    if decision.open_issue:
        if dry_run:
            print(f"dry run, not opening: {decision.title}")
        else:
            api.ensure_label()
            print(f"opened {api.create_issue(decision.title, decision.body)}")
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dry-run", action="store_true", help="decide and print, write nothing")
    args = parser.parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and not args.dry_run:
        print("GITHUB_TOKEN is not set", file=sys.stderr)
        return 2
    repo = os.environ.get("GITHUB_REPOSITORY") or DEFAULT_REPO
    run(Api(repo, token), dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())

import contextlib
import importlib.util
import io
import sys
import unittest
from pathlib import Path

# The script lives in .github/scripts, which is not an importable package.
_PATH = Path(__file__).resolve().parent / ".github" / "scripts" / "game_data_watch.py"
_SPEC = importlib.util.spec_from_file_location("game_data_watch", _PATH)
watch = importlib.util.module_from_spec(_SPEC)
sys.modules["game_data_watch"] = watch  # dataclasses look their module up here
_SPEC.loader.exec_module(watch)

SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
TITLE = "CNRELWin7.2.0_R48600000_S48600001_D48600002"
RELEASE = watch.Release("v0.2.2-T-3", watch.parse_time("2026-10-20T12:00:00Z"))


def dump(title=TITLE, committed="2026-11-01T10:00:00.000+08:00", sha=SHA):
    return watch.Dump(
        sha=sha,
        title=title,
        committed_at=watch.parse_time(committed),
        url=f"https://gitlab.com/Dimbreath/animegamedata2/-/commit/{sha}",
    )


class DecisionTest(unittest.TestCase):
    def test_a_newer_dump_with_no_issue_opens_one(self):
        decision = watch.decide(dump(), RELEASE, [])
        self.assertTrue(decision.open_issue)
        self.assertEqual(decision.title, "Game data CNRELWin7.2.0 (D48600002) available")
        for text in [SHA, "7.2.0", TITLE, dump().url, "Create Release", "real login", "v0.2.2-T-3"]:
            self.assertIn(text, decision.body)

    def test_a_dump_older_than_the_latest_release_is_skipped(self):
        decision = watch.decide(dump(committed="2026-10-01T00:00:00.000+08:00"), RELEASE, [])
        self.assertFalse(decision.open_issue)
        self.assertIn("v0.2.2-T-3", decision.reason)

    def test_a_dump_committed_as_the_release_was_published_is_carried(self):
        self.assertFalse(watch.decide(dump(committed="2026-10-20T12:00:00Z"), RELEASE, []).open_issue)

    def test_times_compare_as_instants_across_time_zones(self):
        # 19:30 at +08:00 is 11:30Z, half an hour before the release.
        early = dump(committed="2026-10-20T19:30:00.000+08:00")
        self.assertFalse(watch.decide(early, RELEASE, []).open_issue)
        # 20:30 at +08:00 is 12:30Z, after it.
        late = dump(committed="2026-10-20T20:30:00.000+08:00")
        self.assertTrue(watch.decide(late, RELEASE, []).open_issue)

    def test_an_issue_already_filed_for_the_dump_skips_it(self):
        filed = [
            watch.Issue(7, "Game data CNRELWin7.2.0 (D48600002) available", ""),
            # Retitled by hand: the commit in the body still identifies it.
            watch.Issue(8, "ship 7.2 data", f"- Commit: `{SHA}`"),
            watch.Issue(9, f"Game data something odd ({SHA[:8]}) available", ""),
        ]
        for issue in filed:
            with self.subTest(issue=issue.number):
                decision = watch.decide(dump(), RELEASE, [issue])
                self.assertFalse(decision.open_issue)
                self.assertIn(f"#{issue.number}", decision.reason)

    def test_an_issue_for_an_earlier_dump_does_not_count(self):
        earlier = watch.Issue(
            3,
            "Game data CNRELWin7.1.0 (D48533839) available",
            "- Commit: `792978e5503ecfba73dcb3562ed44a0d35a2abe2`",
        )
        self.assertTrue(watch.decide(dump(), RELEASE, [earlier]).open_issue)

    def test_a_malformed_title_opens_anyway_with_the_raw_title(self):
        decision = watch.decide(dump(title="Update data for the new version"), RELEASE, [])
        self.assertTrue(decision.open_issue)
        self.assertEqual(
            decision.title, f"Game data Update data for the new version ({SHA[:8]}) available"
        )
        self.assertIn("Update data for the new version", decision.body)
        self.assertIn("unknown", decision.body)

    def test_with_no_release_yet_any_dump_opens_one(self):
        decision = watch.decide(dump(), None, [])
        self.assertTrue(decision.open_issue)
        self.assertIn("no release yet", decision.body)


class TitleTest(unittest.TestCase):
    def test_reads_the_build_version_and_data_revision(self):
        self.assertEqual(
            watch.parse_dump_title("CNRELWin7.1.0_R48379043_S48511369_D48533839"),
            watch.DumpName("CNRELWin7.1.0", "7.1.0", "D48533839"),
        )
        self.assertEqual(
            watch.parse_dump_title("OSRELWin6.0.0_R1_S2_D3").version, "6.0.0"
        )

    def test_without_a_data_revision_the_commit_names_the_issue(self):
        name = watch.parse_dump_title("CNRELWin7.2.0_R48600000")
        self.assertEqual(name, watch.DumpName("CNRELWin7.2.0", "7.2.0", None))
        decision = watch.decide(dump(title="CNRELWin7.2.0_R48600000"), RELEASE, [])
        self.assertEqual(decision.title, f"Game data CNRELWin7.2.0 ({SHA[:8]}) available")

    def test_other_shapes_are_not_parsed(self):
        for title in ["", "7.1.0", "Update", "CNRELWin7.1_R1", "CNRELWin7.1.0 and more"]:
            with self.subTest(title=title):
                self.assertIsNone(watch.parse_dump_title(title))


class FakeHttp:
    """Stands in for `http_request`: canned answers keyed by (method, url)."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, method, url, token="", payload=None):
        self.calls.append((method, url, payload))
        return self.answers.get((method, url), (404, None))

    def posts(self):
        return [(url, payload) for method, url, payload in self.calls if method == "POST"]


REPO_API = f"{watch.GITHUB_API}/repos/tawan475/irminsul"
ISSUES_URL = f"{REPO_API}/issues?labels=game-data&state=all&per_page=100&page=1"


def answers(*, label_exists, issues=()):
    return {
        ("GET", watch.DUMP_COMMITS_URL): (
            200,
            [
                {
                    "id": SHA,
                    "title": TITLE,
                    "committed_date": "2026-11-01T10:00:00.000+08:00",
                    "web_url": f"https://gitlab.com/Dimbreath/animegamedata2/-/commit/{SHA}",
                }
            ],
        ),
        ("GET", f"{REPO_API}/releases?per_page=30"): (
            200,
            [{"tag_name": "v0.2.2-T-3", "published_at": "2026-10-20T12:00:00Z", "draft": False}],
        ),
        ("GET", ISSUES_URL): (200, list(issues)),
        ("GET", f"{REPO_API}/labels/game-data"): (200, {}) if label_exists else (404, None),
        ("POST", f"{REPO_API}/labels"): (201, {}),
        ("POST", f"{REPO_API}/issues"): (201, {"html_url": "https://github.com/x/y/issues/12"}),
    }


def quietly(f, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return f(*args, **kwargs)


GIT_LOG = f"{SHA}\0" + "2026-11-01T10:00:00+08:00\0" + TITLE + "\n"


class FakeGit:
    """Stands in for `run_git`: `clone` succeeds without touching the
    network, `log` prints `log_output`, and `fail` makes every call raise
    the way `run_git` does when git is missing."""

    def __init__(self, log_output=GIT_LOG, fail=None):
        self.log_output = log_output
        self.fail = fail
        self.calls = []

    def __call__(self, args):
        self.calls.append(list(args))
        if self.fail:
            raise RuntimeError(self.fail)
        if args[0] == "clone":
            return ""
        if "log" in args:
            return self.log_output
        raise AssertionError(f"unexpected git call {args}")


def api(http, token="token", git=None):
    return watch.Api("tawan475/irminsul", token, http, git or FakeGit())


class RunTest(unittest.TestCase):
    def test_creates_the_label_when_missing_and_opens_the_issue(self):
        http = FakeHttp(answers(label_exists=False))
        decision = quietly(watch.run, api(http))

        self.assertTrue(decision.open_issue)
        (label_url, label), (issue_url, issue) = http.posts()
        self.assertEqual(label_url, f"{REPO_API}/labels")
        self.assertEqual(label["name"], "game-data")
        self.assertEqual(issue_url, f"{REPO_API}/issues")
        self.assertEqual(issue["labels"], ["game-data"])
        self.assertEqual(issue["title"], "Game data CNRELWin7.2.0 (D48600002) available")

    def test_an_existing_label_is_left_alone(self):
        http = FakeHttp(answers(label_exists=True))
        quietly(watch.run, api(http))
        self.assertEqual([url for url, _ in http.posts()], [f"{REPO_API}/issues"])

    def test_a_dry_run_writes_nothing(self):
        http = FakeHttp(answers(label_exists=False))
        decision = quietly(watch.run, api(http, token=""), dry_run=True)
        self.assertTrue(decision.open_issue)
        self.assertEqual(http.posts(), [])

    def test_pull_requests_are_not_issues(self):
        # A pull request quoting the commit must not count as its issue.
        pull = {"number": 5, "title": "x", "body": SHA, "pull_request": {}}
        http = FakeHttp(answers(label_exists=True, issues=[pull]))
        self.assertTrue(quietly(watch.run, api(http)).open_issue)

    def test_an_existing_issue_found_through_the_api_skips_the_dump(self):
        filed = {"number": 4, "title": "Game data CNRELWin7.2.0 (D48600002) available", "body": ""}
        http = FakeHttp(answers(label_exists=True, issues=[filed]))
        self.assertFalse(quietly(watch.run, api(http)).open_issue)
        self.assertEqual(http.posts(), [])

    def test_drafts_are_not_releases_and_prereleases_are(self):
        http = FakeHttp(
            {
                ("GET", f"{REPO_API}/releases?per_page=30"): (
                    200,
                    [
                        {"tag_name": "draft", "published_at": None, "draft": True},
                        {"tag_name": "v1-T-2", "published_at": "2026-10-21T00:00:00Z", "prerelease": True},
                        {"tag_name": "v1-T-1", "published_at": "2026-10-20T00:00:00Z"},
                    ],
                )
            }
        )
        self.assertEqual(api(http, token="").latest_release().tag, "v1-T-2")


class GitDumpTest(unittest.TestCase):
    def test_reads_the_newest_commit_from_a_tree_less_shallow_clone(self):
        git = FakeGit()
        found = watch.newest_dump_from_git(git)
        self.assertEqual(found, dump(committed="2026-11-01T10:00:00+08:00"))

        clone, log = git.calls
        self.assertEqual(clone[0], "clone")
        for arg in ["--bare", "--filter=tree:0", watch.DUMP_GIT_URL]:
            self.assertIn(arg, clone)
        self.assertEqual(clone[clone.index("--depth") + 1], "1")
        # The log reads the clone that was just made.
        self.assertEqual(log[:2], ["--git-dir", clone[-1]])
        self.assertIn(f"--format={watch.LOG_FORMAT}", log)

    def test_parses_git_log_output(self):
        sha, committed_at, title = watch.parse_log(f"{SHA.upper()}\x002026-10-01T23:32:38Z\x00A title: with\ttabs\r\n")
        self.assertEqual(sha, SHA)
        self.assertEqual(committed_at, watch.parse_time("2026-10-02T07:32:38+08:00"))
        self.assertEqual(title, "A title: with\ttabs")
        # An empty subject is still a commit.
        self.assertEqual(watch.parse_log(f"{SHA}\x002026-10-01T23:32:38+00:00\x00\n")[2], "")

    def test_unexpected_git_log_output_is_an_error(self):
        for output in ["", "\n", f"{SHA}\n", f"{SHA[:12]}\x002026-10-01T00:00:00Z\x00t", f"{SHA}\x00yesterday\x00t"]:
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    watch.parse_log(output)

    def test_the_run_reads_the_dump_from_git_not_the_api(self):
        http = FakeHttp(answers(label_exists=True))
        quietly(watch.run, api(http))
        self.assertNotIn(("GET", watch.DUMP_COMMITS_URL, None), http.calls)

    def test_without_git_the_api_answers(self):
        http = FakeHttp(answers(label_exists=True))
        found = quietly(api(http, git=FakeGit(fail="git is not installed")).newest_dump)
        self.assertEqual(found, dump())
        self.assertIn(("GET", watch.DUMP_COMMITS_URL, None), http.calls)

    def test_when_both_fail_the_error_names_both(self):
        def cloudflare(method, url, token="", payload=None):
            raise RuntimeError(f"GET {url} failed with 403: a Cloudflare bot check page instead of JSON")

        with self.assertRaises(RuntimeError) as caught:
            quietly(api(cloudflare, git=FakeGit(fail="git clone failed (128)")).newest_dump)
        message = str(caught.exception)
        self.assertIn("git clone failed", message)
        self.assertIn("Cloudflare bot check", message)

    def test_run_git_reports_a_missing_git(self):
        def missing(*args, **kwargs):
            raise FileNotFoundError("git")

        original = watch.subprocess.run
        watch.subprocess.run = missing
        try:
            with self.assertRaisesRegex(RuntimeError, "not installed"):
                watch.run_git(["--version"])
        finally:
            watch.subprocess.run = original


class HtmlTest(unittest.TestCase):
    CHALLENGE = b"<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>"

    def test_an_html_answer_is_recognised(self):
        self.assertTrue(watch.looks_like_html("text/html; charset=UTF-8", b"{}"))
        self.assertTrue(watch.looks_like_html("application/json", b"\n  <html></html>"))
        self.assertTrue(watch.looks_like_html(None, self.CHALLENGE))
        self.assertFalse(watch.looks_like_html("application/json", b'[{"id": "x"}]'))
        self.assertFalse(watch.looks_like_html(None, b""))

    def test_a_cloudflare_challenge_is_named(self):
        self.assertEqual(watch.html_kind(self.CHALLENGE), "a Cloudflare bot check page")
        self.assertEqual(watch.html_kind(b"<html>maintenance</html>"), "an HTML page")


if __name__ == "__main__":
    unittest.main()

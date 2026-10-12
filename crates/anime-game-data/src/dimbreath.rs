use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::GameDataSource;

/// The dump's repository, for `git ls-remote`. gitlab.com serves git over
/// HTTPS without the Cloudflare bot check that its REST API sometimes answers
/// with, so git is asked first.
const REPO_GIT_URL: &str = "https://gitlab.com/Dimbreath/animegamedata2.git";
/// The same question through GitLab's REST API: the fallback for a machine
/// where git cannot answer.
const COMMITS_API_URL: &str =
    "https://gitlab.com/api/v4/projects/83871005/repository/commits?per_page=1";
const REPO_BASE_URL: &str = "https://gitlab.com/Dimbreath/animegamedata2/-/raw";

/// `git ls-remote` takes about a second; this only stops a hung connection
/// from hanging the build.
const GIT_TIMEOUT: Duration = Duration::from_secs(60);

/// The one field of a GitLab commit this reads.
#[derive(Debug, Deserialize)]
struct GitLabCommitEntry {
    id: String,
}

pub struct Dimbreath {
    client: reqwest::Client,
}

impl Dimbreath {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder().gzip(true).build()?,
        })
    }

    async fn api_latest_hash(&self) -> Result<String> {
        let response = self
            .client
            .get(COMMITS_API_URL)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("Failed to fetch commits")?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = response
            .text()
            .await
            .context("Failed to read the commits answer")?;
        parse_commits_answer(status, content_type.as_deref(), &body)
    }
}

impl GameDataSource for Dimbreath {
    /// The commit the dump's default branch points at: from `git ls-remote`,
    /// or from GitLab's REST API when git cannot answer (not installed, or
    /// failed).
    async fn get_latest_hash(&self) -> Result<String> {
        let git_error = match git_latest_hash(REPO_GIT_URL, GIT_TIMEOUT) {
            Ok(hash) => return Ok(hash),
            Err(e) => e,
        };
        tracing::warn!("git could not read the dump's HEAD ({git_error:#}); asking the GitLab API");
        self.api_latest_hash().await.map_err(|api_error| {
            anyhow!(
                "unable to find the newest dump commit: git: {git_error:#}; GitLab API: \
                 {api_error:#}"
            )
        })
    }

    async fn get_json_file<T: DeserializeOwned>(&self, git_ref: &str, path: &str) -> Result<T> {
        let url = format!("{REPO_BASE_URL}/{git_ref}/{path}");
        self.client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to send request for {url}"))?
            .json::<T>()
            .await
            .with_context(|| format!("Failed to parse {url}"))
    }
}

/// `git ls-remote <repo> HEAD`, read.
fn git_latest_hash(repo: &str, timeout: Duration) -> Result<String> {
    let stdout = run_with_timeout("git", &["ls-remote", repo, "HEAD"], timeout)?;
    parse_ls_remote_head(&stdout)
}

/// Runs `program` with `args` and returns its standard output, failing when it
/// cannot be started, exits unsuccessfully or outlives `timeout` (then it is
/// killed).
fn run_with_timeout(program: &str, args: &[&str], timeout: Duration) -> Result<String> {
    let command_line = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        // Never wait for someone to type a password: the repository is public,
        // and a build has no one at the keyboard.
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("unable to run `{command_line}` (is {program} installed?)"))?;

    // Read both pipes on their own threads so a chatty child can never block
    // on a full pipe while this waits for it to exit.
    let stdout = read_in_background(child.stdout.take());
    let stderr = read_in_background(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            // The reader threads are left to finish on their own: a helper
            // git started may still hold the pipes open.
            bail!(
                "`{command_line}` did not finish within {}s",
                timeout.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(20));
    };

    let stdout = stdout.join().unwrap_or_default();
    if !status.success() {
        let stderr = stderr.join().unwrap_or_default();
        bail!(
            "`{command_line}` failed ({status}): {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    String::from_utf8(stdout).with_context(|| format!("`{command_line}` printed non-UTF-8 output"))
}

fn read_in_background<R: Read + Send + 'static>(pipe: Option<R>) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// A full commit id: 40 hex digits (SHA-1) or 64 (SHA-256).
fn is_commit_hash(text: &str) -> bool {
    matches!(text.len(), 40 | 64) && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The commit `HEAD` names in `git ls-remote <repo> HEAD` output, whose lines
/// are `<sha>\t<ref>`.
fn parse_ls_remote_head(output: &str) -> Result<String> {
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let (Some(sha), Some("HEAD")) = (fields.next(), fields.next()) else {
            continue;
        };
        // `--symref` adds `ref: refs/heads/main\tHEAD`; that is not a commit.
        if sha == "ref:" {
            continue;
        }
        if !is_commit_hash(sha) {
            bail!("git ls-remote named HEAD with {sha:?}, which is not a commit id");
        }
        return Ok(sha.to_ascii_lowercase());
    }
    bail!(
        "git ls-remote did not name a HEAD commit (output: {:?})",
        snippet(output)
    )
}

/// The newest commit in a GitLab `repository/commits` answer.
///
/// An HTML page in place of JSON is how gitlab.com's Cloudflare front answers
/// a request it wants a browser for ("Just a moment..."), so it gets its own
/// error rather than a JSON parse failure.
fn parse_commits_answer(status: u16, content_type: Option<&str>, body: &str) -> Result<String> {
    let is_html = content_type.is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"))
        || body.trim_start().starts_with('<');
    if is_html {
        let what = if body.contains("Just a moment") || body.contains("challenge-platform") {
            "a Cloudflare bot check page"
        } else {
            "an HTML page"
        };
        bail!("gitlab.com answered HTTP {status} with {what} instead of JSON");
    }
    if !(200..300).contains(&status) {
        bail!("the GitLab API answered HTTP {status}: {:?}", snippet(body));
    }
    let commits: Vec<GitLabCommitEntry> = serde_json::from_str(body).with_context(|| {
        format!(
            "the GitLab API's answer is not a list of commits: {:?}",
            snippet(body)
        )
    })?;
    let Some(newest) = commits.first() else {
        bail!("the GitLab API listed no commits");
    };
    if !is_commit_hash(&newest.id) {
        bail!(
            "the GitLab API named {:?}, which is not a commit id",
            newest.id
        );
    }
    Ok(newest.id.to_ascii_lowercase())
}

/// The start of `text`, for an error message.
fn snippet(text: &str) -> String {
    text.trim().chars().take(200).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn ls_remote_head_is_read() {
        assert_eq!(
            parse_ls_remote_head(&format!("{SHA}\tHEAD\n")).unwrap(),
            SHA
        );
        // `--symref` output, CRLF, upper case, and another ref after it.
        let output = format!(
            "ref: refs/heads/main\tHEAD\r\n{}\tHEAD\r\n{SHA}\trefs/heads/main\r\n",
            SHA.to_ascii_uppercase()
        );
        assert_eq!(parse_ls_remote_head(&output).unwrap(), SHA);
    }

    #[test]
    fn ls_remote_without_head_is_an_error() {
        for output in ["", "\n", &format!("{SHA}\trefs/heads/main\n")] {
            let error = parse_ls_remote_head(output).unwrap_err().to_string();
            assert!(error.contains("did not name a HEAD"), "{error}");
        }
    }

    #[test]
    fn ls_remote_head_must_be_a_commit_id() {
        for sha in ["0123abc", "<html>", &"g".repeat(40)] {
            let error = parse_ls_remote_head(&format!("{sha}\tHEAD\n"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("not a commit id"), "{error}");
        }
        let sha256 = "a".repeat(64);
        assert_eq!(
            parse_ls_remote_head(&format!("{sha256}\tHEAD\n")).unwrap(),
            sha256
        );
    }

    #[test]
    fn api_answer_is_read() {
        let body = format!(
            r#"[{{"id":"{SHA}","title":"x"}},{{"id":"{}"}}]"#,
            "f".repeat(40)
        );
        assert_eq!(
            parse_commits_answer(200, Some("application/json"), &body).unwrap(),
            SHA
        );
    }

    #[test]
    fn a_cloudflare_challenge_is_named_not_parsed() {
        let page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head>\
                    <body><script src=\"/cdn-cgi/challenge-platform/x.js\"></script></body></html>";
        let error = parse_commits_answer(403, Some("text/html; charset=UTF-8"), page)
            .unwrap_err()
            .to_string();
        assert!(error.contains("Cloudflare bot check"), "{error}");
        assert!(error.contains("403"), "{error}");
        assert!(!error.contains("parse"), "{error}");

        // Even when the header claims JSON.
        let error = parse_commits_answer(200, Some("application/json"), "\n<html>hi</html>")
            .unwrap_err()
            .to_string();
        assert!(error.contains("HTML page instead of JSON"), "{error}");
    }

    #[test]
    fn api_errors_say_what_came_back() {
        let error = parse_commits_answer(500, None, r#"{"message":"500 Internal"}"#)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("HTTP 500") && error.contains("500 Internal"),
            "{error}"
        );

        let error = parse_commits_answer(200, None, "[]")
            .unwrap_err()
            .to_string();
        assert!(error.contains("no commits"), "{error}");

        let error = parse_commits_answer(200, None, r#"{"id":"x"}"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a list of commits"), "{error}");

        let error = parse_commits_answer(200, None, r#"[{"id":"main"}]"#)
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a commit id"), "{error}");
    }

    /// The real plumbing, against a repository on disk: no network.
    #[test]
    fn git_reads_the_head_of_a_local_repository() {
        if run_with_timeout("git", &["--version"], Duration::from_secs(30)).is_err() {
            eprintln!("git is not installed; skipping");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().to_str().unwrap();
        let git = |args: &[&str]| {
            let mut all = vec![
                "-C",
                repo,
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@t.invalid",
            ];
            all.extend_from_slice(args);
            run_with_timeout("git", &all, Duration::from_secs(30)).unwrap()
        };
        git(&["init", "-q"]);
        git(&["commit", "-q", "--allow-empty", "-m", "dump"]);
        let head = git(&["rev-parse", "HEAD"]).trim().to_owned();

        assert_eq!(git_latest_hash(repo, GIT_TIMEOUT).unwrap(), head);

        let error = git_latest_hash(&format!("{repo}/missing"), GIT_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(error.contains("failed"), "{error}");
    }

    #[test]
    fn a_missing_program_is_a_clear_error() {
        let error = run_with_timeout(
            "irminsul-test-no-such-program",
            &["ls-remote"],
            Duration::from_secs(5),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unable to run"), "{error}");
    }
}

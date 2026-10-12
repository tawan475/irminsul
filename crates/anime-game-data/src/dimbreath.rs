use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::GameDataSource;

const COMMITS_API_URL: &str = "https://gitlab.com/api/v4/projects/83871005/repository/commits";
const REPO_BASE_URL: &str = "https://gitlab.com/Dimbreath/animegamedata2/-/raw";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitLabCommitEntry {
    id: String,
    short_id: String,
    created_at: String,
    parent_ids: Vec<String>,
    title: String,
    message: String,
    author_name: Option<String>,
    author_email: Option<String>,
    author_date: Option<String>,
    committer_name: Option<String>,
    committer_email: Option<String>,
    committed_date: Option<String>,
    web_url: String,
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
}

impl GameDataSource for Dimbreath {
    async fn get_latest_hash(&self) -> Result<String> {
        let commits = self
            .client
            .get(COMMITS_API_URL)
            .send()
            .await
            .context("Failed to fetch commits")?
            .json::<Vec<GitLabCommitEntry>>()
            .await
            .context("Failed to parse commits")?;

        Ok(commits[0].id.clone())
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

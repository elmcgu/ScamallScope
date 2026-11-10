# 04 GitHub

## Input

Which repos: the values of tag `scamallscope:repo` (`owner/repo`) on resources in the snapshot.
No tag, no GitHub call. The token (`GITHUB_TOKEN`) is a fine-grained token with
"Deployments: read" on those repos only [R20].

For each repo: `GET https://api.github.com/repos/{owner}/{repo}/deployments?per_page=30` [R18],
then for the newest deployment per environment
`GET /repos/{owner}/{repo}/deployments/{id}/statuses?per_page=1` [R19] (newest first). Headers:
`Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`.

Raw file `integrations/github.json`:
`{"fetched_at": ..., "repos": {"owner/repo": {"deployments": [...], "statuses": {"<id>": [...]}}}}`.

## Matching

Resource tag `scamallscope:repo` and optional `scamallscope:environment` (default
`production`). The resource gets the newest deployment for that repo and environment.

## Output per resource (`deploy`)

`repo`, `environment`, `sha` (first 7 characters), `ref`, `created_at`, `state` (latest status,
or `unknown` when there is none), `url` (`https://github.com/{repo}/deployments`).

## Findings

| Check | When | Severity | BP |
|---|---|---|---|
| `github-deploy-failed` | Latest state `failure` or `error` | high | REL08-BP02 |
| `github-no-deployment` | Tagged repo and environment has no deployment | low | SEC11-BP06 |

Coverage: REL08-BP02 and SEC11-BP06 for each tagged resource.

## Tests

| ID | Given | Then |
|---|---|---|
| GHB-1 | Two deployments to production, newest `success` | `deploy.state` success, newest sha |
| GHB-2 | Newest production deploy status `failure` | Finding `github-deploy-failed`, high |
| GHB-3 | Resource tagged `scamallscope:environment=staging` | Gets the staging deployment |
| GHB-4 | Tagged repo with no deployments | Finding `github-no-deployment` |
| GHB-5 | `repos_from_snapshot` | Unique sorted repos from tags; invalid names (no `/`, spaces) skipped |
| GHB-6 | fetch with fake urlopen | Bearer token header, API version header, one status call per environment |

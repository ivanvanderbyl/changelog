# Changelog CLI

This CLI exports commit activity for every repository in a GitHub organisation into CSV format. It relies on your existing `gh` authentication to reach private repos and is designed to help assemble evidence for Australian R&D Tax Incentive claims.

## Prerequisites

- Go 1.25 or newer.
- A valid `gh auth login` session with access to the organisation whose data you are exporting.

## Run

```bash
go run . \
  --org Alcova-AI \
  --fy 25 \
  --ignore-user ivanvanderbyl \
  > commits.csv
```

### Flags

- `--org` *(required)*: GitHub organisation slug.
- `--fy` *(required)*: Australian financial year (e.g. `25` for FY24-25).
- `--main-branch`: Base branch used when checking merge status (defaults to `main`).
- `--ignore-user`: Repeatable flag to exclude specific GitHub usernames as author, committer, or co-author—ideal for filtering out contributors located outside Australia.

## Output

The CLI streams CSV rows with headers:

```
repository,branch,sha,date,author,author_login,author_email,committer,committer_login,committer_email,co_authors,message
```

Timestamps are emitted in Australia/Sydney time, commit SHAs are short (7 characters), and commit messages are trimmed to the first line. Duplicate commits across branches are collapsed so each SHA appears once. Progress logs are written to stderr.***

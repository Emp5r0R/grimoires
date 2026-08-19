# GitHub Email Guard

A small CLI tool to scan GitHub/Git history for exposed email addresses and safely replace selected emails in commit history.

## Features

- Fast GitHub API scanning
- Deep Git history scanning
- Email replacement with `git-filter-repo`
- Backup and verification before pushing
- Protected branch, rate-limit, network, and partial-push handling
- JSON reports

## Requirements

- Python 3.9+
- `aiohttp`
- Git 2.36+
- `git-filter-repo` for rewriting

Install Python dependency:

```bash
pip install aiohttp git-filter-repo
```

## Usage

### Scan an account

```bash
python github_email_guard.py scan --account USERNAME
```

### Deep scan

```bash
python github_email_guard.py deep-scan --account USERNAME
```

### Replace an email

Test locally first:

```bash
python github_email_guard.py rewrite OWNER/REPO \
  --old-email old@example.com \
  --new-email 123+user@users.noreply.github.com \
  --no-push
```

Run again without `--no-push` when ready to update the remote repository.

### Scan and replace

```bash
python github_email_guard.py scan-rewrite \
  --account USERNAME \
  --old-email old@example.com \
  --new-email 123+user@users.noreply.github.com \
  --no-push
```

## GitHub Token

For better API limits and private repository access:

```bash
export GITHUB_TOKEN="your_token"
```

## Help

```bash
python github_email_guard.py --help
python github_email_guard.py scan --help
python github_email_guard.py rewrite --help
```
## Credits
Partial code of Scanner is yanked from my homie's repo https://github.com/i-vt/InterestingSnippets/blob/main/Python/ParseAllUsersGithubReposAndFindLeakedEmailsInGitConfigUserEmail.py 

## Warning

Rewriting Git history changes commit IDs. Use `--no-push` first, review the results, and make sure collaborators re-clone or correctly update old clones afterward.

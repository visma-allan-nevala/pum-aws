# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

pum-aws is a CLI tool for Visma employees to obtain temporary AWS credentials via SAML federated authentication through Visma's ADFS identity provider. It supports optional 1Password CLI integration for automatic credential retrieval.

## Build and Run Commands

```bash
# Recommended: Auto-setup and run (creates venv if needed)
./scripts/run.sh [options]

# Manual setup
./scripts/setup.sh              # Creates venv, installs dependencies
source venv/bin/activate
python pum_aws.py [options]

# Docker
./pum-aws.sh [options]
```

**Requirements**: Python 3.9+

## Key CLI Options

- `--role TEXT` - Role name to assume
- `-p, --profile TEXT` - AWS profile name (default: default)
- `-a, --account TEXT` - Filter roles by AWS account ID
- `-r, --region TEXT` - AWS region (default: eu-central-1)
- `-m, --profiles TEXT` - Comma-separated profiles for batch mode
- `-d, --duration INT` - Token duration 1-3 hours (default: 1)
- `-o, --no-op` - Disable 1Password integration

All options can also be set via environment variables (prefix `PUM_`), see `.env.example`.

## Architecture

Single-file CLI application (`pum_aws.py`, ~450 lines) with procedural flow:

```
User Input → 1Password CLI (optional) → ADFS Form Submission
→ SAML Assertion Extraction → AWS STS assume_role_with_saml
→ Write to ~/.aws/credentials
```

**Key libraries**:
- `requests` - ADFS HTTP communication
- `beautifulsoup4` - HTML form parsing
- `boto3` - AWS STS credential exchange
- `xml.etree.ElementTree` - SAML assertion parsing

**Config files**:
- `.env` - Local environment overrides (git-ignored)
- `~/.pum-aws` - Stores last username and account aliases
- `~/.aws/credentials` - Generated AWS credentials

## Testing

No automated tests. Manual verification:
```bash
aws sts get-caller-identity
```

## AWS Environment (Allan's Access)

| Environment | Account ID | Role | Profile |
|-------------|------------|------|---------|
| Development | 841677801897 | development-developer-a-tiimi | default |

**Current access**: Only development environment via `ADM\A57406_CPA`

To authenticate:
```bash
./scripts/run.sh
```

To check current identity:
```bash
aws sts get-caller-identity
```

**Note**: Staging/production access may require different credentials or admin provisioning.

## Git Preferences

- **Always push to `personal` remote** (visma-allan-nevala), never to `origin` (Visma-Netvisor)
- **No AI attribution in commits**: Do not include "Co-Authored-By", "Generated with Claude Code", or any mention of Claude/AI in commit messages
- Keep commit messages clean and concise

```bash
git push personal
```

## Important Notes

- Python version is enforced at runtime (3.9+)
- Token duration clamped to 1-3 hours (AWS STS limit)
- SAML parsing handles ARN/principal swap automatically
- 1Password integration auto-detected and optional

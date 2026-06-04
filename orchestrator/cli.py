"""
sentinel CLI — entry point for the Sentinel autonomous remediation agent.

Usage:
    sentinel fix-cve --repo https://github.com/org/repo
    sentinel fix-cve --repo https://github.com/org/repo --branch develop --llm gemini
"""
import os
import sys

# Ensure sibling modules (factory, remediator, llm_client) are importable
sys.path.insert(0, os.path.dirname(__file__))

import click
from dotenv import load_dotenv

load_dotenv()


@click.group()
@click.version_option(package_name="sentinel-remediation")
def sentinel():
    """Sentinel — autonomous CVE remediation agent.

    Forks a repo, patches vulnerable dependencies and source code,
    verifies the build in an isolated Docker sandbox, and opens a PR.
    """
    pass


@sentinel.command("fix-cve")
@click.option("--repo", required=True, help="GitHub repo URL to remediate.")
@click.option("--branch", default="main", show_default=True, help="Branch or tag to target.")
@click.option(
    "--llm",
    default=None,
    type=click.Choice(["anthropic", "gemini"], case_sensitive=False),
    help="LLM provider (default: auto-detect from env).",
)
@click.option("--model", default=None, help="Override the default model for the chosen provider.")
def fix_cve(repo: str, branch: str, llm: str, model: str):
    """Detect CVEs in REPO, patch source + build files, verify, open a PR."""
    if llm:
        os.environ["LLM_PROVIDER"] = llm.lower()
    if model:
        provider = (llm or os.getenv("LLM_PROVIDER", "")).lower()
        if provider == "gemini":
            os.environ["GEMINI_MODEL"] = model
        else:
            os.environ["ANTHROPIC_MODEL"] = model

    _check_prerequisites()

    from factory import RemediationFactory
    click.echo(f"\n🔍  Scanning {repo} @ {branch} ...")
    factory = RemediationFactory()
    pr_url = factory.execute_ephemeral_fix(repo, branch)

    if pr_url:
        click.echo(f"\n✅  PR opened: {pr_url}")
    else:
        click.echo("\n❌  Remediation did not produce a PR. Check output above.", err=True)
        sys.exit(1)


def _check_prerequisites():
    """Fail fast with clear messages if required env vars or Docker are missing."""
    missing = []
    if not os.getenv("GITHUB_TOKEN"):
        missing.append("GITHUB_TOKEN")
    if not os.getenv("ANTHROPIC_API_KEY") and not os.getenv("GEMINI_API_KEY"):
        missing.append("ANTHROPIC_API_KEY or GEMINI_API_KEY")
    if missing:
        click.echo(f"❌  Missing required environment variables: {', '.join(missing)}", err=True)
        click.echo("    Copy .env.example → .env and fill in the values.", err=True)
        sys.exit(1)

    try:
        import docker
        docker.from_env().ping()
    except Exception:
        click.echo("❌  Docker is not running. Start Docker Desktop and try again.", err=True)
        sys.exit(1)

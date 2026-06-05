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


@sentinel.command("scan-org")
@click.option("--org", required=True, help="GitHub org name (e.g. ford-bedrock-platform).")
@click.option("--severity", multiple=True,
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW"], case_sensitive=False),
              default=["CRITICAL", "HIGH"], show_default=True,
              help="Only report findings at or above this severity.")
@click.option("--language", multiple=True,
              help="Filter by repo language (e.g. --language java --language python).")
@click.option("--include", default=None, help="Glob pattern for repo names to include (e.g. 'bedrock-*').")
@click.option("--exclude", default=None, help="Glob pattern for repo names to exclude (e.g. '*-test').")
@click.option("--max-repos", default=50, show_default=True, help="Max repos to scan.")
@click.option("--create-prs", is_flag=True, default=False,
              help="Create remediation PRs for affected repos (requires Docker + LLM key).")
@click.option("--report", default=None, help="Output HTML report path (default: sentinel-report-{org}.html).")
@click.option("--json-out", default=None, help="Also write a JSON report to this path.")
@click.option("--github-url", default="https://api.github.com", show_default=True,
              help="GitHub API URL (override for GitHub Enterprise).")
def scan_org(org, severity, language, include, exclude, max_repos,
             create_prs, report, json_out, github_url):
    """Scan all repos in a GitHub org for CVEs and generate a report.

    By default runs in dry-run mode — no PRs are created unless --create-prs is set.

    \b
    Examples:
      sentinel scan-org --org my-org
      sentinel scan-org --org my-org --severity CRITICAL --language java --create-prs
      sentinel scan-org --org my-org --include "platform-*" --report security.html
    """
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        click.echo("❌  GITHUB_TOKEN not set.", err=True)
        raise SystemExit(1)

    if create_prs:
        _check_prerequisites()

    from org_scanner import OrgScanner
    from report import generate_html, generate_json

    report_path = report or f"sentinel-report-{org}.html"

    scanner = OrgScanner(gh_token=token, github_url=github_url)

    scanned = [0]
    def on_progress(current, total, result):
        scanned[0] = current
        status = "❌" if result.scan_error else ("🔴" if result.affected else "✅")
        cve_str = f" ({len(result.findings)} CVEs)" if result.findings else ""
        click.echo(f"  [{current:>3}/{total}] {status} {result.name}{cve_str}")

    click.echo(f"\n🔍  Scanning {org} "
               f"(severity: {', '.join(severity)}"
               f"{', languages: ' + ', '.join(language) if language else ''}) ...\n")

    results = scanner.scan(
        org=org,
        languages=list(language) if language else None,
        severities=list(severity),
        include_pattern=include,
        exclude_pattern=exclude,
        max_repos=max_repos,
        on_progress=on_progress,
    )

    if create_prs:
        click.echo(f"\n⚙️   Creating PRs for affected repos...")
        scanner.create_prs_for_results(results, severities=list(severity))

    # Summary
    affected = [r for r in results if r.affected]
    prs = [r for r in results if r.pr_url]
    all_cves = sum(len(r.findings) for r in results)

    click.echo(f"\n{'─'*50}")
    click.echo(f"  Repos scanned:    {len(results)}")
    click.echo(f"  Affected repos:   {len(affected)}")
    click.echo(f"  CVEs found:       {all_cves}")
    if prs:
        click.echo(f"  PRs created:      {len(prs)}")

    sev_counts = {}
    for r in affected:
        for f in r.findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(sev):
            click.echo(f"  {sev:<16}  {sev_counts[sev]}")
    click.echo(f"{'─'*50}\n")

    generate_html(results, org=org, out_path=report_path, dry_run=not create_prs)
    click.echo(f"📄  Report: {report_path}")

    if json_out:
        generate_json(results, org=org, out_path=json_out)
        click.echo(f"📄  JSON:   {json_out}")

    if not create_prs and affected:
        click.echo(f"\n   Run with --create-prs to open remediation PRs automatically.")


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

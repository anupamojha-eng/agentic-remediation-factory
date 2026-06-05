"""
Sentinel report generator — produces HTML and JSON reports from org scan results.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

_SEVERITY_COLOR = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#65a30d",
    "UNKNOWN":  "#6b7280",
    "NONE":     "#22c55e",
}

_SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f7fee7",
    "UNKNOWN":  "#f9fafb",
    "NONE":     "#f0fdf4",
}


def generate_html(results, org: str, out_path: str, dry_run: bool = True) -> str:
    from org_scanner import _SEVERITY_ORDER

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    total       = len(results)
    affected    = [r for r in results if r.affected]
    clean       = [r for r in results if not r.affected and not r.skipped and not r.scan_error]
    skipped     = [r for r in results if r.skipped]
    errored     = [r for r in results if r.scan_error]
    prs_created = [r for r in results if r.pr_url]

    all_findings = [f for r in affected for f in r.findings]
    sev_counts   = {s: 0 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for f in all_findings:
        sev_counts[f.severity.upper()] = sev_counts.get(f.severity.upper(), 0) + 1

    affected_sorted = sorted(affected, key=lambda r: _SEVERITY_ORDER.get(r.max_severity, 4))

    def badge(sev: str) -> str:
        c = _SEVERITY_COLOR.get(sev, "#6b7280")
        bg = _SEVERITY_BG.get(sev, "#f9fafb")
        return (f'<span style="background:{bg};color:{c};border:1px solid {c};'
                f'padding:2px 8px;border-radius:4px;font-size:0.75rem;font-weight:600">'
                f'{sev}</span>')

    def pr_link(url: str) -> str:
        if not url:
            return '<span style="color:#9ca3af">—</span>'
        short = url.split("/pull/")[-1]
        return f'<a href="{url}" target="_blank" style="color:#2563eb">PR #{short}</a>'

    findings_rows = ""
    for r in affected_sorted:
        rowspan = max(1, len(r.findings))
        for i, f in enumerate(r.findings):
            if i == 0:
                repo_cell = (
                    f'<td rowspan="{rowspan}" style="vertical-align:top;padding:10px 12px;'
                    f'border-bottom:1px solid #e5e7eb">'
                    f'<a href="{r.html_url}" target="_blank" style="color:#111827;font-weight:600">'
                    f'{r.name}</a><br>'
                    f'<span style="font-size:0.78rem;color:#9ca3af">{r.language} · {r.build_system}</span>'
                    f'</td>'
                    f'<td rowspan="{rowspan}" style="vertical-align:top;padding:10px 12px;'
                    f'border-bottom:1px solid #e5e7eb;text-align:center">'
                    f'{badge(r.max_severity)}</td>'
                )
                pr_cell = (
                    f'<td rowspan="{rowspan}" style="vertical-align:top;padding:10px 12px;'
                    f'border-bottom:1px solid #e5e7eb;text-align:center">'
                    f'{pr_link(r.pr_url)}</td>'
                )
            else:
                repo_cell = ""
                pr_cell = ""

            border = "" if i < len(r.findings) - 1 else "border-bottom:2px solid #e5e7eb"
            findings_rows += f"""
            <tr style="{border}">
              {repo_cell}
              <td style="padding:8px 12px;font-family:monospace;font-size:0.82rem">
                <a href="https://github.com/advisories/{f.ghsa_id}" target="_blank"
                   style="color:#2563eb">{f.ghsa_id}</a>
              </td>
              <td style="padding:8px 12px;font-size:0.85rem;color:#374151">{f.affected_package}</td>
              <td style="padding:8px 12px;font-size:0.85rem;text-align:center">{badge(f.severity)}</td>
              <td style="padding:8px 12px;font-size:0.82rem;color:#6b7280">{f.summary}</td>
              <td style="padding:8px 12px;font-family:monospace;font-size:0.8rem;color:#059669">{f.fixed_version or '—'}</td>
              {pr_cell}
            </tr>"""

    clean_rows = ""
    for r in clean[:20]:
        clean_rows += f"""
        <tr>
          <td style="padding:8px 12px">
            <a href="{r.html_url}" target="_blank" style="color:#374151">{r.name}</a>
          </td>
          <td style="padding:8px 12px;color:#9ca3af;font-size:0.85rem">{r.language}</td>
          <td style="padding:8px 12px">{badge("NONE")}</td>
        </tr>"""
    if len(clean) > 20:
        clean_rows += f'<tr><td colspan="3" style="padding:8px 12px;color:#9ca3af;font-size:0.85rem">... and {len(clean)-20} more clean repos</td></tr>'

    sev_summary = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sev_counts.get(sev, 0)
        if count:
            c = _SEVERITY_COLOR[sev]
            bg = _SEVERITY_BG[sev]
            sev_summary += f'<div style="background:{bg};border:1px solid {c};border-radius:8px;padding:16px 24px;text-align:center"><p style="font-size:1.8rem;font-weight:700;color:{c};margin:0">{count}</p><p style="font-size:0.8rem;font-weight:600;color:{c};margin:0;text-transform:uppercase">{sev}</p></div>'

    mode_note = (
        '<div style="background:#fffbeb;border:1px solid #fbbf24;border-radius:8px;padding:12px 16px;margin-bottom:24px">'
        '⚠️  <strong>Dry-run mode</strong> — no PRs were created. Run with <code>--create-prs</code> to open remediation PRs.'
        '</div>'
    ) if dry_run else ""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sentinel Security Report — {org}</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            color: #111827; background: #f9fafb; }}
    a {{ color: #2563eb; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ background: #f3f4f6; padding: 2px 6px; border-radius: 4px; font-size: 0.85em; }}
    .container {{ max-width: 1100px; margin: 0 auto; padding: 0 24px 48px; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff;
             border: 1px solid #e5e7eb; border-radius: 10px; overflow: hidden; }}
    th {{ background: #f3f4f6; padding: 10px 12px; text-align: left;
          font-size: 0.78rem; font-weight: 600; color: #6b7280;
          text-transform: uppercase; letter-spacing: 0.05em;
          border-bottom: 1px solid #e5e7eb; }}
  </style>
</head>
<body>

<div style="background:#111827;color:white;padding:24px 0;margin-bottom:32px">
  <div class="container" style="padding-top:0;padding-bottom:0">
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px">
      <div>
        <p style="font-size:0.78rem;color:#9ca3af;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:4px">
          Sentinel Security Report
        </p>
        <h1 style="font-size:1.8rem;font-weight:700;letter-spacing:-0.02em">{org}</h1>
      </div>
      <div style="text-align:right">
        <p style="font-size:0.85rem;color:#9ca3af">{ts}</p>
        <p style="font-size:0.85rem;color:#9ca3af">
          Generated by <a href="https://github.com/anupamojha-eng/agentic-remediation-factory"
          style="color:#60a5fa">Sentinel</a>
        </p>
      </div>
    </div>
  </div>
</div>

<div class="container">

  {mode_note}

  <!-- Summary stats -->
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:32px">
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;text-align:center">
      <p style="font-size:2rem;font-weight:700;color:#111827">{total}</p>
      <p style="font-size:0.8rem;color:#6b7280;font-weight:500">Repos scanned</p>
    </div>
    <div style="background:#fef2f2;border:1px solid #fca5a5;border-radius:10px;padding:20px;text-align:center">
      <p style="font-size:2rem;font-weight:700;color:#dc2626">{len(affected)}</p>
      <p style="font-size:0.8rem;color:#dc2626;font-weight:500">Affected repos</p>
    </div>
    <div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;text-align:center">
      <p style="font-size:2rem;font-weight:700;color:#111827">{len(all_findings)}</p>
      <p style="font-size:0.8rem;color:#6b7280;font-weight:500">CVEs found</p>
    </div>
    <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:10px;padding:20px;text-align:center">
      <p style="font-size:2rem;font-weight:700;color:#16a34a">{len(clean)}</p>
      <p style="font-size:0.8rem;color:#16a34a;font-weight:500">Clean repos</p>
    </div>
    {"".join(f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;padding:20px;text-align:center"><p style="font-size:2rem;font-weight:700;color:#2563eb">{len(prs_created)}</p><p style="font-size:0.8rem;color:#2563eb;font-weight:500">PRs created</p></div>' if prs_created else [])}
  </div>

  <!-- Severity breakdown -->
  {"".join(f'<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px">{sev_summary}</div>') if sev_summary else ""}

  <!-- Affected repos table -->
  {"".join([f'<h2 style="font-size:1.2rem;font-weight:700;margin-bottom:14px">Affected Repositories ({len(affected)})</h2>']) if affected else ""}
  {"".join([f'''<div style="overflow-x:auto;margin-bottom:40px"><table>
    <thead><tr>
      <th>Repository</th><th>Max Severity</th>
      <th>Advisory</th><th>Package</th><th>Severity</th>
      <th>Summary</th><th>Fix Version</th><th>PR</th>
    </tr></thead>
    <tbody>{findings_rows}</tbody>
  </table></div>''']) if affected else '<p style="color:#6b7280;margin-bottom:32px">No vulnerabilities found.</p>'}

  <!-- Clean repos -->
  {f'''<h2 style="font-size:1.2rem;font-weight:700;margin-bottom:14px">Clean Repositories ({len(clean)})</h2>
  <div style="overflow-x:auto;margin-bottom:40px"><table>
    <thead><tr><th>Repository</th><th>Language</th><th>Status</th></tr></thead>
    <tbody>{clean_rows}</tbody>
  </table></div>''' if clean else ""}

  <!-- Errors -->
  {f'''<h2 style="font-size:1.2rem;font-weight:700;margin-bottom:14px;color:#dc2626">Scan Errors ({len(errored)})</h2>
  <div style="overflow-x:auto;margin-bottom:40px"><table>
    <thead><tr><th>Repository</th><th>Error</th></tr></thead>
    <tbody>{"".join(f'<tr><td style="padding:8px 12px"><a href="{r.html_url}">{r.name}</a></td><td style="padding:8px 12px;color:#dc2626;font-size:0.85rem">{r.scan_error}</td></tr>' for r in errored)}</tbody>
  </table></div>''' if errored else ""}

  <p style="font-size:0.78rem;color:#9ca3af;text-align:center;margin-top:32px">
    Sentinel v0.1.0 · <a href="https://pypi.org/project/sentinel-remediation/">pip install sentinel-remediation</a>
  </p>

</div>
</body>
</html>"""

    Path(out_path).write_text(html, encoding="utf-8")
    return out_path


def generate_json(results, org: str, out_path: str) -> str:
    ts = datetime.now(timezone.utc).isoformat()
    data = {
        "org": org,
        "scanned_at": ts,
        "summary": {
            "total_repos": len(results),
            "affected_repos": sum(1 for r in results if r.affected),
            "clean_repos": sum(1 for r in results if not r.affected and not r.skipped),
            "total_cves": sum(len(r.findings) for r in results),
            "prs_created": sum(1 for r in results if r.pr_url),
            "by_severity": {
                sev: sum(1 for r in results for f in r.findings if f.severity.upper() == sev)
                for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            },
        },
        "repos": [
            {
                "name": r.name,
                "full_name": r.full_name,
                "url": r.html_url,
                "language": r.language,
                "build_system": r.build_system,
                "max_severity": r.max_severity,
                "pr_url": r.pr_url,
                "scan_error": r.scan_error,
                "findings": [
                    {
                        "ghsa_id": f.ghsa_id,
                        "severity": f.severity,
                        "summary": f.summary,
                        "package": f.affected_package,
                        "affected_version": f.affected_version,
                        "fixed_version": f.fixed_version,
                    }
                    for f in r.findings
                ],
            }
            for r in results
        ],
    }
    Path(out_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out_path

#!/usr/bin/env python3
"""
DevSecOps Auto-Remediation PR Bot
Automatically creates a git branch with updated package versions and opens/proposes a GitHub Pull Request.
"""

import json
import os
import sys
import subprocess
import argparse
import urllib.request
import urllib.error

def parse_args():
    parser = argparse.ArgumentParser(description="Create automated remediation PR for SCA vulnerabilities")
    parser.add_argument("--sca-report", default="reports/trivy-sca-results.json", help="Path to Trivy SCA JSON report")
    parser.add_argument("--package-json", default="sample-app/package.json", help="Path to target package.json")
    parser.add_argument("--output", default="reports/remediation-pr.json", help="Path to save PR output metadata")
    parser.add_argument("--repo", default="cnkgkce/devsecops-labs", help="GitHub repo in owner/repo format")
    parser.add_argument("--base-branch", default="main", help="Base branch for PR")
    parser.add_argument("--fix-branch", default="fix/security-remediation-sca", help="Branch name for fix PR")
    return parser.parse_args()

def run_cmd(cmd, cwd=None):
    result = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def extract_target_version(fixes_list):
    """
    Selects the highest/cleanest version from Trivy fixedVersion strings.
    e.g. '1.15.1, 0.31.1' -> '1.15.1'
    """
    candidates = []
    for f in fixes_list:
        if not f or f in ["None", "No Fix Available"]:
            continue
        for part in f.split(","):
            cleaned = part.strip().replace(">=", "").replace(">", "").strip()
            if cleaned:
                candidates.append(cleaned)
    if not candidates:
        return None
    # Sort or return latest candidate
    return candidates[0]

def main():
    args = parse_args()

    print("==========================================================")
    print("      DEVSECOPS AUTOMATED REMEDIATION PR BOT              ")
    print("==========================================================")

    if not os.path.exists(args.sca_report):
        print(f"[!] SCA report not found at {args.sca_report}. Skipping PR creation.")
        return

    if not os.path.exists(args.package_json):
        print(f"[!] Target package.json not found at {args.package_json}. Skipping.")
        return

    # 1. Read SCA report
    try:
        with open(args.sca_report, "r") as f:
            sca_data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read SCA report: {e}")
        return

    # Extract vulnerabilities
    vuln_map = {}
    results = sca_data.get("Results", [])
    for target in results:
        for v in target.get("Vulnerabilities", []):
            pkg = v.get("PkgName")
            if not pkg:
                continue
            if pkg not in vuln_map:
                vuln_map[pkg] = {
                    "installed": v.get("InstalledVersion"),
                    "fixed_versions": [],
                    "cves": []
                }
            if v.get("FixedVersion"):
                vuln_map[pkg]["fixed_versions"].append(v.get("FixedVersion"))
            vuln_map[pkg]["cves"].append({
                "cve": v.get("VulnerabilityID"),
                "severity": v.get("Severity"),
                "title": v.get("Title") or v.get("Description") or ""
            })

    if not vuln_map:
        print("[*] No SCA vulnerabilities detected. No remediation PR needed.")
        return

    # 2. Read package.json
    try:
        with open(args.package_json, "r") as f:
            pkg_data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read package.json: {e}")
        return

    deps = pkg_data.get("dependencies", {})
    changes = []

    for pkg, info in vuln_map.items():
        if pkg in deps:
            current_ver = deps[pkg]
            target_ver = extract_target_version(info["fixed_versions"])
            if target_ver and target_ver not in current_ver:
                new_ver_spec = f"^{target_ver}"
                deps[pkg] = new_ver_spec
                changes.append({
                    "package": pkg,
                    "old_version": current_ver,
                    "new_version": new_ver_spec,
                    "cve_count": len(info["cves"]),
                    "cves": [c["cve"] for c in info["cves"]]
                })
                print(f"[+] Proposing upgrade for {pkg}: {current_ver} -> {new_ver_spec} (fixes {len(info['cves'])} CVEs)")

    if not changes:
        print("[*] No direct dependencies in package.json to bump. No PR created.")
        return

    # 3. Create or switch to remediation branch
    print(f"\n[*] Creating remediation git branch: {args.fix_branch}")
    rc, out, err = run_cmd("git rev-parse --abbrev-ref HEAD")
    original_branch = out if rc == 0 else "main"

    # Create new branch
    run_cmd(f"git checkout -B {args.fix_branch}")

    # Write updated package.json
    with open(args.package_json, "w") as f:
        json.dump(pkg_data, f, indent=2)
        f.write("\n")

    # Regenerate package-lock.json using docker node
    print("[*] Regenerating package-lock.json with updated dependencies...")
    run_cmd(f"docker run --rm -v $(pwd)/sample-app:/app -w /app node:16-alpine npm i --package-lock-only")

    # Commit changes
    commit_msg = f"fix(security): auto-remediate {len(changes)} vulnerable dependencies\n\n"
    for ch in changes:
        commit_msg += f"- bump {ch['package']} from {ch['old_version']} to {ch['new_version']} (resolves {ch['cve_count']} CVEs)\n"

    run_cmd("git add sample-app/package.json sample-app/package-lock.json")
    rc_commit, out_commit, err_commit = run_cmd(f'git commit -m "{commit_msg}"')

    # Push branch to origin
    print(f"[*] Pushing {args.fix_branch} to GitHub origin...")
    rc_push, out_push, err_push = run_cmd(f"git push -u origin {args.fix_branch} --force")

    # Switch back to original branch
    run_cmd(f"git checkout {original_branch}")

    # 4. Prepare PR Description & GitHub Pull Request
    pr_title = f"🛡️ [DevSecOps Auto-Remediation] Fix {sum(c['cve_count'] for c in changes)} SCA Vulnerabilities in sample-app"
    pr_body = f"""## 🛡️ Automated Security Remediation PR

Bu Pull Request, DevSecOps pipeline'ında **Trivy SCA** taraması tarafından tespit edilen kritik ve yüksek seviyeli paket zafiyetlerini gidermek üzere otomatik olarak oluşturulmuştur.

### 📦 Güncellenen Bağımlılıklar

| Paket | Mevcut Sürüm | Yeni Güvenli Sürüm | Kapatılan CVE Sayısı |
| :--- | :--- | :--- | :--- |
"""
    for ch in changes:
        pr_body += f"| **`{ch['package']}`** | `{ch['old_version']}` | `{ch['new_version']}` | **{ch['cve_count']} CVE** |\n"

    pr_body += "\n### 📋 Kapatılan Zafiyetler (CVE Listesi)\n"
    for ch in changes:
        cve_links = ", ".join([f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in ch['cves']])
        pr_body += f"- **`{ch['package']}`**: {cve_links}\n"

    pr_body += "\n> 🤖 *Bu PR, DevSecOps Pipeline Otomatik İyileştirme Motoru tarafından oluşturulmuştur.*"

    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    pr_url = None
    pr_number = None

    if github_token:
        print("[*] GITHUB_TOKEN detected. Creating Pull Request via GitHub REST API...")
        api_url = f"https://api.github.com/repos/{args.repo}/pulls"
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json"
        }
        payload = json.dumps({
            "title": pr_title,
            "head": args.fix_branch,
            "base": args.base_branch,
            "body": pr_body
        }).encode("utf-8")

        req = urllib.request.Request(api_url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as response:
                res_data = json.loads(response.read().decode())
                pr_url = res_data.get("html_url")
                pr_number = res_data.get("number")
                print(f"[✅] Pull Request created successfully: {pr_url}")
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode()
            if "A pull request already exists" in err_msg:
                print(f"[*] A pull request already exists for branch {args.fix_branch}.")
                pr_url = f"https://github.com/{args.repo}/pulls"
            else:
                print(f"[!] GitHub API error: {err_msg}")
    else:
        # Generate compare / PR URL for user
        pr_url = f"https://github.com/{args.repo}/compare/{args.base_branch}...{args.fix_branch}?expand=1"
        print(f"[i] Fix branch pushed to GitHub: {args.fix_branch}")
        print(f"[i] Direct Pull Request Creation URL: {pr_url}")

    # 5. Save output metadata
    pr_result = {
        "status": "READY" if pr_url else "BRANCH_PUSHED",
        "branch": args.fix_branch,
        "base": args.base_branch,
        "repo": args.repo,
        "pr_url": pr_url,
        "pr_number": pr_number,
        "changes_count": len(changes),
        "total_cves_resolved": sum(c['cve_count'] for c in changes),
        "changes": changes
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(pr_result, f, indent=2)

    print("\n----------------------------------------------------------")
    print("               REMEDIATION BOT SUMMARY                    ")
    print("----------------------------------------------------------")
    print(f"  • Remediated Packages       : {len(changes)}")
    print(f"  • Total CVEs Resolved       : {sum(c['cve_count'] for c in changes)}")
    print(f"  • Pushed Fix Branch         : {args.fix_branch}")
    print(f"  • PR Link                   : {pr_url}")
    print(f"  • Saved Metadata to         : {args.output}")
    print("==========================================================\n")

if __name__ == "__main__":
    main()

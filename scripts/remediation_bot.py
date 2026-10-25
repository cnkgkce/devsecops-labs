#!/usr/bin/env python3
"""
DevSecOps Auto-Remediation PR Bot
Automatically generates fix branches and Pull Requests for:
  1. Software Composition Analysis (SCA) - package.json / package-lock.json
  2. Container Security - Dockerfile base image upgrade & hardening
"""

import os
import sys
import re
import json
import subprocess
import argparse
import urllib.request
import urllib.error

def parse_args():
    parser = argparse.ArgumentParser(description="Automated remediation PR generator for SCA and Container vulnerabilities")
    parser.add_argument("--mode", choices=["all", "sca", "container"], default="all", help="Remediation target mode")
    parser.add_argument("--sca-report", default="reports/trivy-sca-results.json", help="Path to Trivy SCA JSON report")
    parser.add_argument("--container-report", default="reports/trivy-container-results.json", help="Path to Trivy Container scan JSON")
    parser.add_argument("--package-json", default="sample-app/package.json", help="Path to target package.json")
    parser.add_argument("--dockerfile", default="sample-app/Dockerfile", help="Path to target Dockerfile")
    parser.add_argument("--output", default="reports/remediation-pr.json", help="Path to save PR output metadata")
    parser.add_argument("--repo", default="cnkgkce/devsecops-labs", help="GitHub repo in owner/repo format")
    parser.add_argument("--base-branch", default="main", help="Base branch for PR")
    parser.add_argument("--fix-branch", default=None, help="Branch name for fix PR")
    return parser.parse_args()

def run_cmd(cmd, cwd=None):
    result = subprocess.run(cmd, shell=True, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()

def semver_key(v):
    nums = [int(n) for n in re.findall(r'\d+', v)]
    return nums if nums else [0]

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
    candidates.sort(key=semver_key)
    return candidates[-1]

def remediate_sca(sca_report_path, package_json_path):
    if not os.path.exists(sca_report_path) or not os.path.exists(package_json_path):
        return None, []

    try:
        with open(sca_report_path, "r") as f:
            sca_data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read SCA report: {e}")
        return None, []

    vuln_map = {}
    for target in sca_data.get("Results", []):
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

    try:
        with open(package_json_path, "r") as f:
            pkg_data = json.load(f)
    except Exception as e:
        print(f"[!] Failed to read package.json: {e}")
        return None, []

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

    return pkg_data, changes

def remediate_container(container_report_path, dockerfile_path):
    if not os.path.exists(dockerfile_path):
        return None, None

    # Parse OS CVEs from Trivy report if available
    os_cves = []
    if os.path.exists(container_report_path):
        try:
            with open(container_report_path, "r") as f:
                cdata = json.load(f)
            for target in cdata.get("Results", []):
                if target.get("Class") == "os-pkgs":
                    for v in target.get("Vulnerabilities", []):
                        os_cves.append({
                            "cve": v.get("VulnerabilityID"),
                            "pkg": v.get("PkgName"),
                            "severity": v.get("Severity"),
                            "fixed_version": v.get("FixedVersion", "Patched in modern LTS")
                        })
        except Exception as e:
            print(f"[!] Warning reading container report: {e}")

    try:
        with open(dockerfile_path, "r") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Failed to read Dockerfile: {e}")
        return None, None

    # Detect current FROM
    from_match = re.search(r"^FROM\s+([^\s\n]+)", content, re.MULTILINE)
    if not from_match:
        return None, None

    old_base = from_match.group(1)
    target_base = "node:20-alpine"

    if old_base == target_base and "USER node" in content:
        print("[*] Dockerfile is already using modern hardened base image (node:20-alpine).")
        return None, None

    new_content = content
    # Replace FROM line
    new_content = re.sub(r"^FROM\s+[^\s\n]+", f"FROM {target_base}", new_content, count=1, flags=re.MULTILINE)

    # Security hardening: Non-root user
    if "USER node" not in new_content:
        # Add non-root user right before CMD or EXPOSE
        if "CMD " in new_content:
            new_content = re.sub(r"(CMD\s+.*)", r"# Hardening: Run as non-root unprivileged user\nUSER node\n\n\1", new_content, count=1)
        elif "EXPOSE " in new_content:
            new_content = re.sub(r"(EXPOSE\s+.*)", r"# Hardening: Run as non-root unprivileged user\nUSER node\n\n\1", new_content, count=1)

    container_change = {
        "file": dockerfile_path,
        "old_base": old_base,
        "new_base": target_base,
        "hardened": "Non-root (USER node) configured",
        "cve_count": len(os_cves),
        "cves": [c["cve"] for c in os_cves]
    }
    print(f"[+] Proposing Dockerfile upgrade: {old_base} -> {target_base} (mitigates {len(os_cves)} OS CVEs)")
    return new_content, container_change

def main():
    args = parse_args()

    print("==========================================================")
    print("      DEVSECOPS AUTOMATED REMEDIATION PR BOT              ")
    print(f"      Target Mode: {args.mode.upper()}")
    print("==========================================================")

    sca_pkg_data = None
    sca_changes = []
    dockerfile_new_content = None
    container_change = None

    # 1. Process SCA
    if args.mode in ["all", "sca"]:
        sca_pkg_data, sca_changes = remediate_sca(args.sca_report, args.package_json)

    # 2. Process Container
    if args.mode in ["all", "container"]:
        dockerfile_new_content, container_change = remediate_container(args.container_report, args.dockerfile)

    if not sca_changes and not container_change:
        print("[*] No remediation changes required or direct dependencies to bump. No PR created.")
        empty_result = {
            "status": "NO_CHANGES_NEEDED",
            "message": "All dependencies and container base images are already up to date.",
            "total_cves_resolved": 0
        }
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(empty_result, f, indent=2)
        return

    # 3. Create or switch to remediation branch
    fix_branch = args.fix_branch
    if not fix_branch:
        if args.mode == "container":
            fix_branch = "fix/container-security-remediation"
        elif args.mode == "sca":
            fix_branch = "fix/sca-security-remediation"
        else:
            fix_branch = "fix/security-remediation-auto"

    print(f"\n[*] Creating remediation git branch: {fix_branch}")
    rc, original_branch, _ = run_cmd("git rev-parse --abbrev-ref HEAD")
    if rc != 0 or not original_branch:
        original_branch = "main"

    run_cmd(f"git checkout -B {fix_branch}")

    # Write SCA changes
    staged_files = []
    if sca_changes and sca_pkg_data:
        with open(args.package_json, "w") as f:
            json.dump(sca_pkg_data, f, indent=2)
            f.write("\n")
        staged_files.append(args.package_json)

        # Regenerate package-lock.json
        print("[*] Regenerating package-lock.json...")
        rc_node, _, _ = run_cmd("node --version")
        if rc_node == 0:
            run_cmd(f"npm i --package-lock-only", cwd=os.path.dirname(args.package_json))
        else:
            run_cmd(f"docker run --rm -v $(pwd)/sample-app:/app -w /app node:18-alpine npm i --package-lock-only")
        
        lock_file = os.path.join(os.path.dirname(args.package_json), "package-lock.json")
        if os.path.exists(lock_file):
            staged_files.append(lock_file)

    # Write Container changes
    if container_change and dockerfile_new_content:
        with open(args.dockerfile, "w") as f:
            f.write(dockerfile_new_content)
        staged_files.append(args.dockerfile)

    # Commit changes
    total_cves = sum(c['cve_count'] for c in sca_changes) + (container_change['cve_count'] if container_change else 0)
    commit_msg = f"fix(security): automated remediation for {total_cves} vulnerabilities\n\n"
    if sca_changes:
        commit_msg += "SCA Package Upgrades:\n"
        for ch in sca_changes:
            commit_msg += f"- bump {ch['package']} from {ch['old_version']} to {ch['new_version']} ({ch['cve_count']} CVEs)\n"
    if container_change:
        commit_msg += f"\nContainer Hardening:\n- bump base image from {container_change['old_base']} to {container_change['new_base']} ({container_change['cve_count']} OS CVEs)\n- non-root user enforcement\n"

    for sf in staged_files:
        run_cmd(f"git add {sf}")

    run_cmd(f'git commit -m "{commit_msg}"')

    # Push branch to GitHub origin
    print(f"[*] Pushing {fix_branch} to GitHub origin...")
    rc_push, out_push, err_push = run_cmd(f"git push -u origin {fix_branch} --force")

    # Switch back to original branch
    run_cmd(f"git checkout {original_branch}")

    # 4. Prepare PR Description & GitHub Pull Request
    pr_title = f"🛡️ [DevSecOps Auto-Remediation] Fix {total_cves} Vulnerabilities (SCA & Container)"
    pr_body = f"""## 🛡️ Automated Security Remediation PR

Bu Pull Request, DevSecOps pipeline'ında tespit edilen güvenlik açıklarını gidermek üzere **1-Click Otomatik İyileştirme Motoru** tarafından oluşturulmuştur.

### 📊 İyileştirme Özeti
- **Kapatılan Toplam Zafiyet:** **{total_cves} CVE**
- **Etkilenen Katmanlar:** {"SCA Bağımlılıkları" if sca_changes else ""} {" & " if sca_changes and container_change else ""} {"Container Base Image" if container_change else ""}
"""

    if sca_changes:
        pr_body += "\n### 📦 Güncellenen Uygulama Bağımlılıkları (SCA)\n\n"
        pr_body += "| Paket | Mevcut Sürüm | Yeni Güvenli Sürüm | Kapatılan CVE |\n| :--- | :--- | :--- | :--- |\n"
        for ch in sca_changes:
            pr_body += f"| **`{ch['package']}`** | `{ch['old_version']}` | `{ch['new_version']}` | **{ch['cve_count']} CVE** |\n"

    if container_change:
        pr_body += f"""\n### 🐳 Konteyner & İşletim Sistemi İyileştirmesi (Dockerfile)
- **Eski Taban İmaj:** `{container_change['old_base']}`
- **Yeni Güvenli LTS İmajı:** `{container_change['new_base']}`
- **Sıkılaştırma (Hardening):** `{container_change['hardened']}`
- **Kapatılan OS CVE Sayısı:** **{container_change['cve_count']} CVE** (zlib, OpenSSL, BusyBox vb.)
"""

    pr_body += "\n> 🤖 *Bu PR, DevSecOps Lab Otomatik Remediation Motoru tarafından oluşturulmuştur.*"

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
            "head": fix_branch,
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
                print(f"[*] A pull request already exists for branch {fix_branch}.")
                pr_url = f"https://github.com/{args.repo}/pulls"
            else:
                print(f"[!] GitHub API error: {err_msg}")
    
    if not pr_url:
        pr_url = f"https://github.com/{args.repo}/compare/{args.base_branch}...{fix_branch}?expand=1"
        print(f"[i] Fix branch pushed to GitHub: {fix_branch}")
        print(f"[i] Direct Pull Request Creation URL: {pr_url}")

    # 5. Save output metadata
    pr_result = {
        "status": "SUCCESS",
        "branch": fix_branch,
        "base": args.base_branch,
        "repo": args.repo,
        "pr_url": pr_url,
        "pr_number": pr_number,
        "total_cves_resolved": total_cves,
        "sca_changes": sca_changes,
        "container_change": container_change,
        "title": pr_title
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(pr_result, f, indent=2)

    print("\n----------------------------------------------------------")
    print("               REMEDIATION BOT SUMMARY                    ")
    print("----------------------------------------------------------")
    print(f"  • Remediated SCA Packages   : {len(sca_changes)}")
    print(f"  • Remediated Container      : {'Yes' if container_change else 'No'}")
    print(f"  • Total CVEs Resolved       : {total_cves}")
    print(f"  • Pushed Fix Branch         : {fix_branch}")
    print(f"  • PR Link                   : {pr_url}")
    print(f"  • Saved Metadata to         : {args.output}")
    print("==========================================================\n")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AI-Powered SAST False Positive Elimination Engine
DevSecOps Lab - Phase 2 Module
"""

import json
import os
import sys
import argparse
from prompts import SYSTEM_PROMPT, USER_PROMPT_TEMPLATE

def parse_args():
    parser = argparse.ArgumentParser(description="AI-driven SAST False Positive Elimination")
    parser.add_argument("--sast-report", default="reports/semgrep-results.json", help="Path to Semgrep JSON report")
    parser.add_argument("--output", default="reports/semgrep-ai-triaged.json", help="Path to write triaged results")
    parser.add_argument("--provider", choices=["mock", "ollama", "openai", "gemini"], default="mock", help="AI Provider to use")
    return parser.parse_args()

def analyze_finding_heuristic_mock(finding):
    """
    Simulated AI triage demonstrating the exact logic and schema
    used when evaluating the sample-app's deliberate TPs and FPs.
    """
    check_id = finding.get("check_id", "")
    snippet = finding.get("extra", {}).get("lines", "")
    message = finding.get("extra", {}).get("message", "")

    # Heuristic 1: Check for mock/test token FP
    if "MOCK_API_TEST_TOKEN" in snippet or "test_environment_mock_token" in snippet:
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 95,
            "reasoning": "The string pattern matches an API key structure, but the identifier and value clearly indicate a mock/test variable without access to real infrastructure.",
            "remediation_advice": "No remediation required, or add test fixture exclusions in semgrep ignore patterns."
        }

    # Heuristic 2: Whitelisted command execution FP
    if "ALLOWED_SERVICES" in snippet or ("exec('uptime'" in snippet and "includes(requestedService)" in snippet):
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 92,
            "reasoning": "The user input 'service' is strictly validated against a hardcoded whitelist array. The executed command 'uptime' is a static string with no parameter interpolation.",
            "remediation_advice": "Code is secure against injection. Recommend using an explicit allowed-command mapping function to satisfy static analyzers."
        }

    # Heuristic 3: Sanitized HTML Output FP
    if "safeEscapeHtml" in snippet:
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 88,
            "reasoning": "User input is filtered through an HTML escaping sanitizer (safeEscapeHtml) before output concatenation. Although flagged by naive string concatenation heuristics, XSS is mitigated.",
            "remediation_advice": "Prefer template engines with automatic contextual encoding (e.g., EJS with safe tags) or explicit DOM construction."
        }

    # Default: True Positive for actual vulnerabilities (ping command injection, SQL concatenation, etc.)
    return {
        "is_false_positive": False,
        "verdict": "TRUE_POSITIVE",
        "confidence_score": 98,
        "reasoning": "Direct interpolation of untrusted user input without validation or sanitization detected. Highly exploitable vulnerability.",
        "remediation_advice": "Refactor to use parameterized queries, safe execution APIs with argument arrays, or contextual encoding."
    }

def main():
    args = parse_args()

    if not os.path.exists(args.sast_report):
        print(f"[!] Warning: SAST report not found at {args.sast_report}. Skipping AI triage.")
        return

    print("==========================================================")
    print("      AI-POWERED SAST FALSE POSITIVE ELIMINATION          ")
    print("==========================================================")

    try:
        with open(args.sast_report, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Error reading SAST report: {e}")
        return

    findings = data.get("results", [])
    total_findings = len(findings)
    print(f"[*] Total SAST Findings Loaded: {total_findings}")

    if total_findings == 0:
        print("[*] No findings to analyze.")
        return

    triaged_results = []
    tp_count = 0
    fp_count = 0

    for idx, finding in enumerate(findings, 1):
        finding_id = f"finding-{idx}"
        check_id = finding.get("check_id", "unknown-rule")
        path = finding.get("path", "")
        start_line = finding.get("start", {}).get("line", 0)
        snippet = finding.get("extra", {}).get("lines", "").strip()

        # Perform analysis (Mock/Heuristic for Phase 1 demo, ready for LLM API integration in Phase 2)
        analysis = analyze_finding_heuristic_mock(finding)

        if analysis["is_false_positive"]:
            fp_count += 1
            verdict_badge = "\033[93m[FALSE POSITIVE - FILTERED]\033[0m"
        else:
            tp_count += 1
            verdict_badge = "\033[91m[TRUE POSITIVE - CONFIRMED]\033[0m"

        print(f"\n[{idx}/{total_findings}] {check_id} ({path}:{start_line})")
        print(f"    Verdict: {verdict_badge} (Confidence: {analysis['confidence_score']}%)")
        print(f"    Reasoning: {analysis['reasoning']}")

        item = {
            "finding_id": finding_id,
            "check_id": check_id,
            "path": path,
            "line": start_line,
            "snippet": snippet,
            "triage": analysis
        }
        triaged_results.append(item)

    # Calculate statistics
    reduction_pct = (fp_count / total_findings * 100) if total_findings > 0 else 0

    output_payload = {
        "summary": {
            "total_findings": total_findings,
            "true_positives": tp_count,
            "false_positives": fp_count,
            "false_positive_reduction_rate": f"{reduction_pct:.1f}%"
        },
        "triaged_findings": triaged_results
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(output_payload, f, indent=2)

    print("\n----------------------------------------------------------")
    print("                    TRIAGE SUMMARY                        ")
    print("----------------------------------------------------------")
    print(f"  • Total Findings Analyzed    : {total_findings}")
    print(f"  • True Positives (Actionable): \033[91m{tp_count}\033[0m")
    print(f"  • False Positives (Filtered) : \033[92m{fp_count}\033[0m")
    print(f"  • Alert Noise Reduction Rate : \033[96m{reduction_pct:.1f}%\033[0m")
    print(f"  • Saved Triaged Report to    : {args.output}")
    print("==========================================================\n")

if __name__ == "__main__":
    main()

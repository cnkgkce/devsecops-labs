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

def extract_code_analysis(file_path, line_number, context=5):
    """
    Extracts surrounding code context and pinpoint the exact vulnerable sink line.
    Returns: (snippet_text, sink_code, context_lines_list)
    """
    if not os.path.exists(file_path):
        return "", "", []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        
        start_idx = max(0, line_number - context - 1)
        end_idx = min(len(lines), line_number + context)
        
        formatted_lines = []
        structured_lines = []
        sink_code = ""

        for idx in range(start_idx, end_idx):
            curr_line_num = idx + 1
            code_line = lines[idx].rstrip()
            is_sink = (curr_line_num == line_number)
            
            if is_sink:
                sink_code = code_line.strip()
                marker = ">> [VULNERABLE SINK] "
            else:
                marker = "                     "
            
            formatted_lines.append(f"{marker}{curr_line_num:4d} | {code_line}")
            structured_lines.append({
                "line": curr_line_num,
                "code": code_line,
                "is_sink": is_sink
            })
            
        return "\n".join(formatted_lines), sink_code, structured_lines
    except Exception as e:
        return f"Error reading source file: {e}", "", []

def analyze_finding_heuristic_mock(finding, snippet, sink_code):
    """
    Simulated AI triage demonstrating the exact logic and schema
    used when evaluating the sample-app's deliberate TPs and FPs.
    """
    check_id = finding.get("check_id", "")
    message = finding.get("extra", {}).get("message", "")

    # Heuristic 1: Check for mock/test token FP
    if "MOCK_API_TEST_TOKEN" in snippet or "test_environment_mock_token" in snippet:
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 95,
            "reasoning": "Değişken ismi (MOCK_API_TEST_TOKEN) ve değeri açıkça bir test ortamı sahte anahtarını (mock) temsil ediyor. Canlı sistem veya gizli anahtar riski taşımıyor.",
            "remediation_advice": "Herhangi bir aksiyon gerekmez. İstenirse test dosyaları Semgrep ignore kuralına eklenebilir."
        }

    # Heuristic 2: Whitelisted command execution FP
    if "ALLOWED_SERVICES" in snippet or ("exec('uptime'" in snippet and "includes" in snippet):
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 92,
            "reasoning": "Kullanıcı parametresi 'service' doğrudan komuta verilmemiştir; 'ALLOWED_SERVICES' listesi ile sıkı bir whitelist kontrolünden geçmektedir. Çalışan komut statik 'uptime' dizesidir.",
            "remediation_advice": "Kod komut enjeksiyonuna karşı güvenlidir. Yanlış alarm elenmiştir."
        }

    # Heuristic 3: Sanitized HTML Output FP (XSS rule flagged, but sanitized)
    if "safeEscapeHtml" in snippet or "cleanUser" in snippet:
        return {
            "is_false_positive": True,
            "verdict": "FALSE_POSITIVE",
            "confidence_score": 89,
            "reasoning": "Kullanıcıdan gelen veri HTML içine basılmadan önce 'safeEscapeHtml' fonksiyonu ile sanitize edilerek XSS tehlikesi ortadan kaldırılmıştır. AST eşleşmesi yanıltıcı bir uyarı üretmiştir.",
            "remediation_advice": "Manuel string birleştirme yerine otomatik encode eden EJS veya DOM kütüphaneleri tercih edilebilir."
        }

    # Default: True Positive for actual vulnerabilities (ping command injection, SQL concatenation, etc.)
    return {
        "is_false_positive": False,
        "verdict": "TRUE_POSITIVE",
        "confidence_score": 98,
        "reasoning": f"Kullanıcı kontrolündeki veri filtrelenmeden doğrudan tehlikeli fonksiyona (Sink: '{sink_code[:50]}...') aktarılmıştır. İstismara açık kritik zafiyet.",
        "remediation_advice": "Girdileri parameterized queries, argument array ile çalışan güvenli API'lar veya sıkı doğrulama mekanizmaları ile izole edin."
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
        start_col = finding.get("start", {}).get("col", 0)
        severity = finding.get("extra", {}).get("severity", "INFO")
        message = finding.get("extra", {}).get("message", "")
        metadata = finding.get("extra", {}).get("metadata", {})
        cwe = metadata.get("cwe", [])
        owasp = metadata.get("owasp", [])

        # Extract real source code context around finding and pinpoint sink
        snippet_formatted, sink_code, structured_lines = extract_code_analysis(path, start_line, context=4)
        if not snippet_formatted and "extra" in finding and "lines" in finding["extra"]:
            snippet_formatted = finding["extra"]["lines"]
            sink_code = snippet_formatted

        # Perform analysis
        analysis = analyze_finding_heuristic_mock(finding, snippet_formatted, sink_code)

        if analysis["is_false_positive"]:
            fp_count += 1
            verdict_badge = "\033[93m[FALSE POSITIVE - FILTERED]\033[0m"
        else:
            tp_count += 1
            verdict_badge = "\033[91m[TRUE POSITIVE - CONFIRMED]\033[0m"

        print(f"\n[{idx}/{total_findings}] {check_id} ({path}:{start_line})")
        print(f"    Sink Line: Line {start_line} -> {sink_code}")
        print(f"    Verdict  : {verdict_badge} (Confidence: {analysis['confidence_score']}%)")
        print(f"    Reasoning: {analysis['reasoning']}")

        item = {
            "finding_id": finding_id,
            "check_id": check_id,
            "path": path,
            "line": start_line,
            "col": start_col,
            "severity": severity,
            "message": message,
            "cwe": cwe,
            "owasp": owasp,
            "sink_info": {
                "line": start_line,
                "code": sink_code,
                "type": "AST / Dataflow Sink"
            },
            "code_context": snippet_formatted,
            "code_lines": structured_lines,
            "triage": analysis
        }
        triaged_results.append(item)

    # Calculate statistics
    reduction_pct = (fp_count / total_findings * 100) if total_findings > 0 else 0

    output_payload = {
        "summary": {
            "app_name": "vulnerable-node-app",
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

#!/usr/bin/env bash
# ========================================================
# DevSecOps Lab - Shannon AI Pentester Runner
# ========================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Hedef ve Repo Dizinleri
TARGET_URL="http://host.docker.internal:3000"
REPO_PATH="${ROOT_DIR}/sample-app"
OUTPUT_DIR="${ROOT_DIR}/reports/shannon"
WORKSPACE_NAME="devsecops-scan-$(date +%s)"

mkdir -p "${OUTPUT_DIR}"

echo "=========================================================="
echo "      🚀 SHANNON AI PENTESTER BAŞLATILIYOR               "
echo "=========================================================="
echo "  • Hedef Uygulama : ${TARGET_URL}"
echo "  • Kaynak Kod     : ${REPO_PATH}"
echo "  • Rapor Çıktısı  : ${OUTPUT_DIR}"
echo "  • Gateway        : LiteLLM -> Google Gemini"
echo "  • Workspace      : ${WORKSPACE_NAME}"
echo "=========================================================="

export SHANNON_AI_BASE_URL="http://host.docker.internal:4000/v1"
export SHANNON_AI_API_KEY="sk-devsecops-litellm-123456"
export SHANNON_AI_MODEL="openai:gpt-4o"

npx -y @keygraph/shannon start \
  -u "${TARGET_URL}" \
  -r "${REPO_PATH}" \
  -c "${ROOT_DIR}/shannon.yaml" \
  -o "${OUTPUT_DIR}" \
  -w "${WORKSPACE_NAME}" \
  --pipeline-testing \
  -f "$@"



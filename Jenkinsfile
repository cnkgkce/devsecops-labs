pipeline {
    agent any

    options {
        ansiColor('xterm')
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '15'))
    }

    environment {
        // Lab ortamında host ile senkronize /workspace veya yerel jenkins workspace
        TARGET_DIR = "${sh(script: 'if [ -d "/workspace" ]; then echo "/workspace"; else echo "."; fi', returnStdout: true).trim()}"
    }

    stages {
        stage('0. Setup & Workspace Prep') {
            steps {
                echo "==== [DevSecOps Lab] Workspace: ${TARGET_DIR} ===="
                sh """
                    cd "${TARGET_DIR}"
                    mkdir -p reports
                    echo "Checking available scanner tools..."
                    python3 --version
                    semgrep --version
                    trivy --version
                    docker --version
                """
            }
        }

        stage('1. SAST - Semgrep Code Scan') {
            steps {
                echo '==== [SAST] Semgrep ile Statik Kod Analizi Başlatılıyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    echo "Scanning sample-app with Semgrep..."
                    
                    # 1. JSON çıktısı: Faz 2 AI modülü ve raporlama için
                    semgrep scan --config auto --json -o reports/semgrep-results.json sample-app/ || true

                    # 2. Konsol çıktısı: Pipeline logunda renkli ve okunabilir görünüm
                    semgrep scan --config auto sample-app/ || true
                    
                    # Özet istatistik
                    if [ -f reports/semgrep-results.json ]; then
                        TOTAL_SAST=\$(jq '.results | length' reports/semgrep-results.json 2>/dev/null || echo "0")
                        echo ">> [SAST] Toplam tespit edilen bulgu sayısı: \${TOTAL_SAST}"
                    fi
                """
            }
        }

        stage('2. SCA - Trivy Filesystem Dependency Scan') {
            steps {
                echo '==== [SCA] Trivy ile Bağımlılık & Paket Zafiyet Taraması Başlatılıyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    echo "Scanning sample-app dependencies with Trivy fs..."
                    
                    # 1. JSON çıktısı
                    trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --format json -o reports/trivy-sca-results.json sample-app/ || true

                    # 2. Konsol tablo çıktısı
                    trivy fs --scanners vuln,secret --severity HIGH,CRITICAL sample-app/ || true
                """
            }
        }

        stage('3. Build - Docker Image') {
            steps {
                echo '==== [Build] Docker İmajı Derleniyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    echo "Building vulnerable-node-app:latest image..."
                    docker build -t vulnerable-node-app:latest sample-app/
                """
            }
        }

        stage('4. Container Security - Trivy Image Scan (OS Only)') {
            steps {
                echo '==== [Container Security] Trivy ile İşletim Sistemi Zafiyet Taraması Başlatılıyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    echo "Scanning container image vulnerable-node-app:latest (OS packages only)..."
                    
                    # 1. JSON formatında kaydet (--pkg-types os ile sadece işletim sistemi seviyesi taranır)
                    trivy image --pkg-types os --severity HIGH,CRITICAL --format json -o reports/trivy-container-results.json vulnerable-node-app:latest || true

                    # 2. Konsol tablo çıktısı
                    trivy image --pkg-types os --severity HIGH,CRITICAL vulnerable-node-app:latest || true
                """
            }
        }

        stage('5. AI Triage - FP Elimination (Faz 2)') {
            steps {
                echo '==== [AI Engine] SAST Bulguları Üzerinde AI Destekli FP Eleme Başlatılıyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    if [ -f ai-engine/analyzer.py ]; then
                        python3 ai-engine/analyzer.py \
                            --sast-report reports/semgrep-results.json \
                            --output reports/semgrep-ai-triaged.json || true
                    else
                        echo "AI Engine scripti bulunamadı, bu adım atlanıyor."
                    fi
                """
            }
        }

        stage('6. Auto-Remediation - Fixed PR Generator') {
            steps {
                echo '==== [Remediation Bot] SCA Zafiyetleri İçin Otomatik Fixed PR Hazırlanıyor ===='
                sh """
                    cd "${TARGET_DIR}"
                    if [ -f scripts/remediation_bot.py ]; then
                        python3 scripts/remediation_bot.py \
                            --sca-report reports/trivy-sca-results.json \
                            --package-json sample-app/package.json \
                            --output reports/remediation-pr.json || true
                    else
                        echo "Remediation bot scripti bulunamadı, bu adım atlanıyor."
                    fi
                """
            }
        }
    }

    post {
        always {
            echo '==== [DevSecOps Lab] Raporlar Arşivleniyor ===='
            sh """
                cd "${TARGET_DIR}"
                if [ -d reports ]; then
                    echo "Generated reports in ${TARGET_DIR}/reports:"
                    ls -la reports/
                fi
            """
            sh 'cp -r "${TARGET_DIR}/reports" ./ || true'
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
        success {
            echo '✅ DevSecOps Pipeline başarıyla tamamlandı!'
        }
        failure {
            echo '❌ DevSecOps Pipeline hata ile sonuçlandı!'
        }
    }
}

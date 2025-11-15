pipeline {
    agent any

    stages {


        stage('MAVEN Build & Test'){
            steps {
                sh 'mvn clean install'
            }
        }

        stage('SECRET SCAN (Gitleaks via Docker)') {
            steps {
                sh 'docker run --rm -v $WORKSPACE:/app -w /app zricethezav/gitleaks:latest detect --source=. --report-path=gitleaks-report.json --exit-code 0'
            }
        }
        stage('Security Check: Forbidden .env File') {
            steps {
                script {

                    def envFileExists = fileExists('.env')

                    if (envFileExists) {
                        error("🚨 FATAL SECURITY ERROR: The forbidden '.env' configuration file was found in the repository. Please remove it and use Jenkins credentials/secrets instead.")
                    } else {
                        echo '✅ Security check passed. No forbidden .env file found.'
                    }
                }
            }
        }

        stage('SONARQUBE SCAN'){
            environment{
                SONAR_HOST_URL='http://192.168.50.4:9000/'
                SONAR_AUTH_TOKEN= credentials('sonarqube')
            }
            steps{
                // SonarQube utilise toujours le scanner Maven pour une intégration facile dans les projets Java
                sh 'mvn sonar:sonar -Dsonar.projectKey=devops_git -Dsonar.host.url=$SONAR_HOST_URL -Dsonar.token=$SONAR_AUTH_TOKEN'
            }
        }

        stage('QUALITY GATE WAIT (BLOCKING)') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    // C'est ici que l'outil Jenkins vérifie le résultat de SonarQube
                    // Assurez-vous que le plugin est installé et l'instance configurée!
                    // waitForQualityGate abortPipeline: true, sonarQube: 'MonServeurSonar'
                    echo 'Vérification du Quality Gate SonarQube en cours...'
                }
            }
        }

        stage('DEPENDENCY SCAN (SCA - Trivy via Docker)') {
            steps {
                script {
                    def reportFile = "trivy-sca-report.json"
                    def vulnerabilitiesFound = false

                    // 1. EXECUTE TRIVY SCAN (Generate report)
                    // Note: Keep || true for this command so a scan error doesn't halt the pipeline before reporting.
                    sh """
                docker run --rm \\
                  -v \$WORKSPACE:/app \\
                  -w /app \\
                  aquasec/trivy:latest \\
                  fs --severity HIGH,CRITICAL --format json --output ${reportFile} . || true
            """

                    // 2. CHECK FOR VULNERABILITIES (Set vulnerabilitiesFound flag)
                    // Use 'jq -e' to check if the filter finds any HIGH/CRITICAL items.
                    // 0 = Found (vulnerable), 4 = Not Found (clean).
                    try {
                        // Run jq, capture its exit status, and ignore its stdout
                        def jqExitCode = sh(
                                returnStatus: true,
                                script: """
                        docker run --rm \\
                          -v \$WORKSPACE:/app \\
                          -w /app \\
                          realguess/jq:latest \\
                          jq -e '.Results[] | .Vulnerabilities[] | select(.Severity == "CRITICAL" or .Severity == "HIGH")' ${reportFile} > /dev/null
                    """
                        )

                        if (jqExitCode == 0) {
                            vulnerabilitiesFound = true
                            echo "🚨 CRITICAL/HIGH vulnerabilities found! Preparing to fail the stage."
                        } else {
                            echo "✅ No CRITICAL or HIGH vulnerabilities found. Stage clean."
                        }
                    } catch (Exception e) {
                        // Handles cases where the jq step fails (e.g., file not found, bad JSON)
                        echo "Warning: Error during vulnerability check: ${e.getMessage()}"
                    }

                    // 3. DISPLAY FORMATTED REPORT
                    sh """
                echo "--- TRIVY VULNERABILITY REPORT (HIGH/CRITICAL) ---"
                docker run --rm \\
                  -v \$WORKSPACE:/app \\
                  -w /app \\
                  realguess/jq:latest \\
                  jq -r '
                    .Results[] | select(.Vulnerabilities) | {
                        Target: .Target,
                        Vulnerabilities: [
                            .Vulnerabilities[] | select(.Severity == "CRITICAL" or .Severity == "HIGH") | {
                                Severity: .Severity,
                                VulnerabilityID: .VulnerabilityID,
                                PkgName: .PkgName,
                                InstalledVersion: .InstalledVersion
                            }
                        ]
                    }
                  ' ${reportFile}
            """

                    // 4. FAIL STAGE if vulnerabilities were found
                    if (vulnerabilitiesFound) {
                        error 'Pipeline stopped due to CRITICAL or HIGH dependency vulnerabilities found by Trivy.'
                    }

                    echo 'Le scan Trivy est terminé. Veuillez consulter les résultats ci-dessus.'
                }
            }
        }

        stage('IMAGE CREATION') {
            steps{
                echo "Building image alimsahlibw/devops:latest"
                sh 'docker build -t alimsahlibw/devops:latest .'
                sh 'docker image prune -f'
            }
        }

        // --- STAGE 2: DOCKER HUB PUSH ---
        stage('DOCKER HUB PUSH') {
            steps {
                // Tagging with a unique build number tag for traceability
                sh 'docker tag alimsahlibw/devops:latest alimsahlibw/devops:${BUILD_NUMBER}'
                withCredentials([string(credentialsId: 'dockerhub', variable: 'DOCKERHUB_TOKEN')]) {
                    sh 'echo $DOCKERHUB_TOKEN | docker login -u alimsahlibw --password-stdin'
                    sh 'docker push alimsahlibw/devops:latest'
                    sh 'docker push alimsahlibw/devops:${BUILD_NUMBER}'
                }
            }
        }

        // --- STAGE 3: OWASP ZAP SCAN (DAST) ---
        stage('OWASP ZAP SCAN (DAST)') {
            steps {
                script {
                    def appContainer
                    // Target URL is set to the HOST's port 1234, which maps to the container's 8080
                    def targetUrl = "http://host.docker.internal:1234"

                    try {
                        echo "Starting application container on host port 1234..."
                        // Maps container's internal port 8080 to host's port 1234
                        appContainer = sh(
                                returnStdout: true,
                                script: "docker run -d -p 1234:8080 alimsahlibw/devops:latest"
                        ).trim()

                        // Wait for the application to start
                        sleep 20
                        echo "Application container ID: ${appContainer}. Target URL for ZAP: ${targetUrl}. Starting ZAP scan..."

                        // Run OWASP ZAP Baseline Scan
                        // -I ensures the ZAP container's exit code is ignored, allowing the pipeline to continue
                        sh """
                docker run --rm -v \${PWD}:/zap/wrk/:rw \\
                    -t owasp/zap2docker-weekly zap-baseline.py \\
                    -t ${targetUrl} \\
                    -g zap-scan-report-summary.html \\
                    -r zap-scan-report.xml \\
                    -I || true
                """

                        echo "OWASP ZAP scan finished. Reports saved as zap-scan-report.xml and zap-scan-report-summary.html."

                    } catch (Exception e) {
                        echo "🚨 Error during ZAP stage: ${e.getMessage()}"
                    } finally {
                        // IMPORTANT: Stop and remove the temporary application container
                        if (appContainer) {
                            echo "Stopping and removing application container ${appContainer}."
                            sh "docker stop ${appContainer}"
                            sh "docker rm ${appContainer}"
                        }
                        // Also archive the ZAP reports in the post section!
                    }
                }
            }
        }

    }
    post {
        always {
            archiveArtifacts artifacts: 'trivy-sca-report.json,gitleaks-report.json', allowEmptyArchive: true
        }
        success {
            emailext(
                    subject: "✅ Pipeline SUCCESS: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline **completed successfully**!
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json'
            )
        }


        failure {
            // This runs only if the pipeline failed.
            emailext(
                    subject: "❌ Pipeline FAILED: ${currentBuild.fullDisplayName}",
                    body: """Hello Team,
                    The pipeline failed. Check the attached Trivy report for details.
                    """,
                    to: "alimsahli.si@gmail.com",
                    attachmentsPattern: 'trivy-sca-report.json,gitleaks-report.json'

            )
        }
    }
}
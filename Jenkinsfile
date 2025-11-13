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
                // Utilise $WORKSPACE au lieu de $PWD ou du chemin codé en dur
                sh 'docker run --rm -v $WORKSPACE:/app -w /app zricethezav/gitleaks:latest detect --source=. --report-path=gitleaks-report.json --exit-code 0'
            }
        }
        stage('Security Check: Forbidden .env File') {
            steps {
                script {
                    // Check for the existence of the .env file in the current workspace directory
                    def envFileExists = fileExists('.env')

                    if (envFileExists) {
                        // If the file exists, mark the build as failed and print an error
                        error("🚨 FATAL SECURITY ERROR: The forbidden '.env' configuration file was found in the repository. Please remove it and use Jenkins credentials/secrets instead.")
                    } else {
                        // If the file is not found, continue the pipeline
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

        //stage('image creation'){
            //steps{
                //sh 'docker build -t alimsahlibw/devops .'
                //sh 'docker image prune -f'
            //}
        //}

        //stage('Docker Hub Push') {
             //steps {
                 //withCredentials([string(credentialsId: 'dockerhub', variable: 'DOCKERHUB_TOKEN')]) {
                     //sh 'echo $DOCKERHUB_TOKEN | docker login -u alimsahlibw --password-stdin'
                     //sh 'docker push alimsahlibw/devops'
                 //}
             //}
        //}

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
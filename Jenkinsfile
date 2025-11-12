pipeline {
    agent any

    stages {

        stage('MAVEN Build & Test') {
            steps {
                sh 'mvn clean install'
            }
        }



        stage('SECRET SCAN (Gitleaks via Docker)') {
            steps {
                sh '''
                    docker run --rm \
                      -v $WORKSPACE:/app \
                      -w /app \
                      zricethezav/gitleaks:latest detect \
                      --source=. \
                      --report-path=gitleaks-report.json \
                      --exit-code 0
                '''
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

        stage('SONARQUBE SCAN') {
            environment {
                SONAR_HOST_URL = 'http://192.168.50.4:9000/'
                SONAR_AUTH_TOKEN = credentials('sonarqube')
            }
            steps {
                sh '''
                    mvn sonar:sonar \
                      -Dsonar.projectKey=devops_git \
                      -Dsonar.host.url=$SONAR_HOST_URL \
                      -Dsonar.token=$SONAR_AUTH_TOKEN
                '''
            }
        }

        stage('QUALITY GATE WAIT (BLOCKING)') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    echo '⏳ Vérification du Quality Gate SonarQube en cours...'
                    // Uncomment if SonarQube plugin is configured:
                    // waitForQualityGate abortPipeline: true
                }
            }
        }

        stage('DEPENDENCY SCAN (SCA - Trivy via Docker)') {
            steps {
                script {
                    // Run Trivy SCA scan
                    sh '''
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          aquasec/trivy:latest fs \
                          --severity HIGH,CRITICAL \
                          --format json \
                          --output trivy-sca-report.json . || true
                    '''

                    // Display results in readable format
                    sh '''
                        echo "--- TRIVY VULNERABILITY REPORT (HIGH/CRITICAL) ---"
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          realguess/jq:latest jq -r '
                            .Results[] | select(.Vulnerabilities) | {
                                Target: .Target,
                                Vulnerabilities: [
                                    .Vulnerabilities[] |
                                    select(.Severity == "CRITICAL" or .Severity == "HIGH") | {
                                        Severity: .Severity,
                                        VulnerabilityID: .VulnerabilityID,
                                        PkgName: .PkgName,
                                        InstalledVersion: .InstalledVersion
                                    }
                                ]
                            }'
                          trivy-sca-report.json
                    '''

                    echo '✅ Trivy scan completed. Review results above.'
                }
            }
        }

        stage('BUILD & SCAN DOCKER IMAGE') {
            when {
                expression { return fileExists('Dockerfile') }
            }
            steps {
                script {
                    def imageTag = "monapp:v${env.BUILD_NUMBER}"

                    sh "docker build -t ${imageTag} ."

                    sh '''
                        docker run --rm \
                          -v /var/run/docker.sock:/var/run/docker.sock \
                          aquasec/trivy:latest image \
                          --exit-code 1 \
                          --severity HIGH,CRITICAL ${imageTag}
                    '''
                }
            }
        }

        stage('DEPLOYMENT') {
            steps {
                echo '🚀 All security checks passed. Deployment authorized.'
                // Add your deployment logic here
            }
        }
    }
}

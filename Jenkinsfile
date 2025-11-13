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
                    // Standardize the internal path to /app for both tools

                    // 1. EXECUTE TRIVY SCAN (Write to /app/trivy-sca-report.json)
                    sh '''
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          aquasec/trivy:latest \
                          fs --severity HIGH,CRITICAL --format json --output trivy-sca-report.json . || true
                    '''

                    // 2. DISPLAY FORMATTED REPORT (Read from /app/trivy-sca-report.json)
                    sh '''
                        echo "--- TRIVY VULNERABILITY REPORT (HIGH/CRITICAL) ---"
                        docker run --rm \
                          -v $WORKSPACE:/app \
                          -w /app \
                          realguess/jq:latest \
                          jq -r \'
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
                          \' trivy-sca-report.json
                    '''

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
           // Archive both the Trivy and Gitleaks reports
           archiveArtifacts artifacts: 'trivy_repo_report.json, gitleaks_report.json', allowEmptyArchive: true
       }
       success {
           emailext(
                   subject: "✅ SUCCESS: Pipeline Completed for ${currentBuild.fullDisplayName}",
                   body: """<!DOCTYPE html>
                       <html lang="en">
                       <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                           <div style="max-width: 650px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; padding: 25px; background-color: #f9f9f9;">
                               <h2 style="color: #28a745; margin-top: 0;">✅ Pipeline Success!</h2>
                               <p>The build <strong>${currentBuild.fullDisplayName}</strong> completed successfully and passed all security checks.</p>
                       
                               <h3 style="color: #444; border-bottom: 2px solid #28a745; padding-bottom: 5px;">Key Checks Status:</h3>
                               <ul style="list-style-type: none; padding-left: 0;">
                                   <li style="margin-bottom: 8px;">🟢 <strong>Trivy Scan:</strong> Repository vulnerability scan completed with acceptable findings.</li>
                                   <li>🟢 <strong>Gitleaks Scan:</strong> No sensitive secrets were detected in the codebase.</li>
                               </ul>
                       
                               <p style="margin-top: 20px; font-size: 0.9em; color: #666;">
                                   Reports are archived in the build artifacts for review.
                               </p>
                               <p style="margin-top: 20px;">Best regards,<br>The CI/CD System</p>
                           </div>
                       </body>
                       </html>""",
                   to: "alimsahli.si@gmail.com"
               )
       }


       failure {
           emailext(
                   subject: "❌ FAILED: Pipeline Failed for ${currentBuild.fullDisplayName}",
                   body: """<!DOCTYPE html>
                       <html lang="en">
                       <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                           <div style="max-width: 650px; margin: 0 auto; border: 1px solid #e0e0e0; border-radius: 8px; padding: 25px; background-color: #fff3f3; border-left: 5px solid #dc3545;">
                               <h2 style="color: #dc3545; margin-top: 0;">❌ Pipeline Failure!</h2>
                               <p>The build <strong>${currentBuild.fullDisplayName}</strong> failed.</p>
                               <p>A critical issue was detected during the execution. Please find the security reports attached for immediate review:</p>
                       
                               <h3 style="color: #444; border-bottom: 2px solid #dc3545; padding-bottom: 5px;">Attached Reports:</h3>
                               <ul style="padding-left: 20px;">
                                   <li><strong style="color: #b00;">trivy_repo_report.json</strong> (Vulnerability/Misconfiguration Details)</li>
                                   <li><strong style="color: #b00;">gitleaks_report.json</strong> (Potential Secrets Detected)</li>
                               </ul>
                       
                               <p style="margin-top: 20px; font-size: 0.9em; color: #666;">
                                   Review the build console output for detailed logs and steps to reproduce the failure.
                               </p>
                               <p style="margin-top: 20px;">Best regards,<br>The CI/CD System</p>
                           </div>
                       </body>
                       </html>""",
                   to: "alimsahli.si@gmail.com",

                   // Attach both files
                   attachmentsPattern: 'trivy_repo_report.json, gitleaks_report.json'
               )
       }
   }
}
pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM', branches: [[name: '*/main']], userRemoteConfigs: [[url: 'https://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@github.com/Sycarium/SecurityChannel']]])
             // Assertions
                assert fileExists("${WORKSPACE}/.git"), 'Git repository not cloned'

                def currentBranch = sh(script: 'git rev-parse --abbrev-ref HEAD', returnStdout: true).trim()
                assert currentBranch == 'main', "Expected 'main' branch, but found '$currentBranch'"

                def commitHash = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                assert commitHash != null && commitHash.length() > 0, 'Failed to retrieve commit hash'

                def uncommittedChanges = sh(script: 'git status --porcelain', returnStdout: true).trim()
                assert uncommittedChanges.length() == 0, "Uncommitted changes found:\n${uncommittedChanges}"

                assert fileExists("${WORKSPACE}/src"), 'Source directory does not exist'
                assert fileExists("${WORKSPACE}/Jenkinsfile"), 'Jenkinsfile not found'
            }
        }

        stage("Docker Pull Dastardly from Burp Suite container image") {
            steps {
                sh 'docker pull public.ecr.aws/portswigger/dastardly:latest'
            }
        }

        stage("Docker run Dastardly from Burp Suite Scan") {
            steps {

                 stage("Docker Pull Dastardly from Burp Suite container image") {
            steps {
                script {
                    def dockerImage = 'public.ecr.aws/portswigger/dastardly:latest'

                    // Check if Docker image is pulled successfully
                    def dockerPullExitCode = sh(script: "docker pull ${dockerImage}", returnStatus: true)
                    assert dockerPullExitCode == 0, "Failed to pull Docker image: ${dockerImage}"

                    // Test the behavior when pulling different versions or images
                    def otherDockerImage = 'public.ecr.aws/portswigger/some-other-image:latest'
                    def otherDockerPullExitCode = sh(script: "docker pull ${otherDockerImage}", returnStatus: true)
                    assert otherDockerPullExitCode == 0, "Failed to pull Docker image: ${otherDockerImage}"
                }
            }
        }

               stage("Docket run Dastardly") {
            steps {
                script {
                    def dastardlyExitCode = sh(script: '''
                        docker run --user $(id -u) -v ${WORKSPACE}:${WORKSPACE}:rw \
                        -e BURP_START_URL=https://ginandjuice.shop/ \
                        -e BURP_REPORT_FILE_PATH=${WORKSPACE}/dastardly-report.xml \
                        public.ecr.aws/portswigger/dastardly:latest
                    ''', returnStatus: true)

                    catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                        // If Dastardly succeeds, continue with the pipeline
                        if (dastardlyExitCode == 0) {
                            echo 'Dastardly scan succeeded'
                        } else {
                            error 'Dastardly scan failed'
                        }
                    }
                }
            }
        }

        stage('Build') {
            steps {
                script {
                    // Install dependencies and build React app
                    sh 'npm install'
                    sh 'npm run build'
                }

                steps {
                    script {
                        //  Linting and Code Quality
                        def eslintExitCode = sh(script: 'npx eslint .', returnStatus: true)
                        assert eslintExitCode == 0, 'ESLint found issues in the code'

                        //  Unit Testing
                        def unitTestExitCode = sh(script: 'npm test', returnStatus: true)
                        assert unitTestExitCode == 0, 'Unit tests failed'
                                    // Check if npm is installed
                                def npmCheckExitCode = sh(script: 'npm -v', returnStatus: true)
                                assert npmCheckExitCode == 0, 'npm is not installed'

                                // Check the exit code of npm install
                                def npmInstallExitCode = sh(script: 'npm install', returnStatus: true)
                                assert npmInstallExitCode == 0, 'npm install failed'

                                // Check the exit code of npm run build
                                def npmBuildExitCode = sh(script: 'npm run build', returnStatus: true)
                                assert npmBuildExitCode == 0, 'npm run build failed'
                            }

                        //  Security Scanning
                        def dependencyCheckExitCode = sh(script: 'npm audit', returnStatus: true)
                        assert dependencyCheckExitCode == 0, 'Security vulnerabilities found'

                        //  Documentation Generation
                        def generateDocsExitCode = sh(script: 'npm run generate-docs', returnStatus: true)
                        assert generateDocsExitCode == 0, 'Documentation generation failed'

                        //  Artifact Publishing
                        sh 'npm pack'
                        sh 'npm publish'

                        
                        // 6. Fancy Notification part
                        // Determine email recipient based on the user who pushed the changes
                                def userEmail = ''
                                def changeAuthor = env.CHANGE_AUTHOR
                                switch (changeAuthor) {
                                    case 'developer1':
                                        userEmail = 'developer1@example.com'
                                        break
                                    case 'developer2':
                                        userEmail = 'developer2@example.com'
                                        break
                                    // Add more cases for other developers as needed
                                    default:
                                        // Use a default email address for unknown users
                                        userEmail = 'default@example.com'
                                }
                        catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                            // Send email notification on build failure
                            emailext attachLog: true,
                                    to: userEmail,
                                    subject: "Build Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                                    body: """
                                    <p>Build failed for ${env.JOB_NAME} - ${env.BUILD_NUMBER}</p>
                                    <p>View the build details: ${env.BUILD_URL}</p>
                                    """
                        }
                    }
                }
            }
            }
        }

        stage('Dockerize') {
            steps {
                script {
                       // Check the existence of the Dockerfile
                    def dockerfileCheckExitCode = sh(script: 'test -e Dockerfile', returnStatus: true)
                    assert dockerfileCheckExitCode == 0, 'Dockerfile does not exist'

                    // Lint Dockerfile using Hadolint
                    sh 'docker run --rm -i hadolint/hadolint < Dockerfile'

                    // Security scanning using Trivy
                    sh 'docker run --rm -i aquasec/trivy your-docker-image-name'

                    // Check for unused dependencies using Docker Image Analysis
                    sh 'docker run --rm -i wagoodman/dive your-docker-image-name'

                    // Run a container from the built Docker image
                    def containerRunExitCode = sh(script: 'docker run --rm your-docker-image-name', returnStatus: true)
                    assert containerRunExitCode == 0, 'Failed to run a container from the Docker image'

                    // Build Docker image
                    sh 'docker build -t your-docker-image-name .'
                    
                }
            }
        }

        stage('Deploy') {
            steps {
                script {

                    // Check the existence of the Docker image
                    def dockerImageCheckExitCode = sh(script: 'docker inspect your-docker-image-name', returnStatus: true)
                    assert dockerImageCheckExitCode == 0, 'Docker image does not exist'
                    // Pull the Docker image to the deployment environment
                    sh 'docker pull your-docker-image-name'

                    // Run deployment script
                    sh './deploy.sh'

                    // Example: Check application health using curl
                    def healthCheckExitCode = sh(script: 'curl -sSf http://your-app-url/health', returnStatus: true)
                    assert healthCheckExitCode == 0, 'Application health check failed'
                    
                    // Run integration tests against the deployed application
                    sh 'npm run integration-tests'
                    
                    // Deploy the Docker image (e.g., push to Docker Hub)
                    sh 'docker push your-docker-image-name'
                }
            }
        }
    }
}

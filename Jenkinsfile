pipeline {
  agent any
  environment {
    SECURECI_THRESHOLD = '50'
    SECURECI_TARGET = '.'
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Install Deps') {
      steps {
        script {
          if (isUnix()) {
            sh '''
              set -euo pipefail
              python -m pip install --upgrade pip
              python -m pip install -r backend/requirements.txt
            '''
          } else {
            bat '''
              python -m pip install --upgrade pip
              python -m pip install -r backend\\requirements.txt
            '''
          }
        }
      }
    }

    stage('SecureCI Scan') {
      steps {
        script {
          int statusCode = 0
          if (isUnix()) {
            statusCode = sh(
              script: """
                set +e
                python -m backend.cli scan --target \"${SECURECI_TARGET}\" --threshold ${SECURECI_THRESHOLD} > secureci-result.json
                exit \$?
              """,
              returnStatus: true
            )
          } else {
            statusCode = bat(
              script: """
                @echo off
                python -m backend.cli scan --target \"%SECURECI_TARGET%\" --threshold %SECURECI_THRESHOLD% > secureci-result.json
                exit /b %ERRORLEVEL%
              """,
              returnStatus: true
            )
          }

          archiveArtifacts artifacts: 'secureci-result.json', onlyIfSuccessful: false
          if (statusCode != 0) {
            error("SecureCI policy failed (exit code ${statusCode}). See secureci-result.json artifact.")
          }
        }
      }
    }
  }
  post {
    always {
      echo 'SecureCI pipeline finished.'
    }
  }
}

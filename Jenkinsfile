pipeline {
  agent any
  environment {
    SECURECI_THRESHOLD = '50'
    SECURECI_TARGET = '.'
  }
  stages {
    stage('SecureCI Scan') {
      steps {
        sh '''
          python -m pip install -r backend/requirements.txt
          python -c "from backend.app import _run_scan; print('SecureCI backend modules import OK')"
        '''
        // In a real Jenkins setup, you'd run the API as a service and call /api/scans.
        // This file is a starter placeholder to show where SecureCI plugs into CI.
      }
    }
  }
}

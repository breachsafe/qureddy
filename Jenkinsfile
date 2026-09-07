// SPDX-FileCopyrightText: 2026 BreachSAFE
// SPDX-License-Identifier: Apache-2.0
//
// QuReddy engine CI. GitHub Actions owns the merge gate (.github/workflows/ci.yml);
// this pipeline covers what Actions cannot: live scans that need an OpenSSL 1.0.2u
// compatibility runtime alongside the pinned 3.5.7 build.
//
// The badssl stage is the reason this file exists. `core.ciphers` rates RC4, DES,
// 3DES, EXPORT, NULL, SEED, IDEA, CAMELLIA and ARIA (#815, #824), and every other
// test for those ratings feeds the classifier cipher *names*. These stages scan
// hosts that negotiate the suites for real.
pipeline {
  agent any

  options {
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '30'))
  }

  triggers {
    // badssl.com is a third-party endpoint. A nightly run catches a change there
    // as well as a regression here, and the two are distinguishable only by
    // reading which assertion moved.
    cron('H 3 * * *')
  }

  environment {
    QUREDDY_OPENSSL = '/opt/homebrew/opt/openssl@3.5/bin/openssl'
    REPORT_DIR      = 'build/jenkins'

    // Deliberately NOT named QUREDDY_LEGACY_OPENSSL here. The engine reads that
    // variable, and a pipeline-wide value reaches the unit stage, where
    // test_local_openssl_supported_lts_patch_scans_successfully resolves the real
    // runtime and fails. Only the stage that needs the compatibility lane exports
    // it under the name the engine looks for.
    LEGACY_OPENSSL = "${HOME}/Library/Caches/qureddy-app/openssl-legacy-docker/bin/openssl"
  }

  stages {
    stage('setup') {
      steps {
        sh 'uv sync --frozen --all-extras --dev'
        sh "mkdir -p ${REPORT_DIR}"
      }
    }

    stage('runtimes') {
      // Both binaries are prerequisites, not optional. Assert them here so a
      // missing runtime reads as an environment failure at the top of the log
      // rather than as a skipped test buried in a later stage.
      steps {
        sh '''
          set -eu
          "$QUREDDY_OPENSSL" version
          "$QUREDDY_OPENSSL" version | grep -q "OpenSSL 3.5" \\
            || { echo "primary lane is not OpenSSL 3.5.x" >&2; exit 1; }

          "$LEGACY_OPENSSL" version
          "$LEGACY_OPENSSL" version | grep -q "OpenSSL 1.0.2" \\
            || { echo "compatibility lane is not OpenSSL 1.0.2x" >&2; exit 1; }

          # The 1.0.2u runtime is worthless for these targets if its EC math is
          # broken: every modern server picks an ECDHE suite first, the handshake
          # fails client-side, and the sweep reports the host as offering nothing
          # (qureddy#817). A macOS-native 1.0.2u build fails exactly here.
          "$LEGACY_OPENSSL" ecparam -name prime256v1 -genkey -noout > /dev/null \\
            || { echo "compatibility lane cannot do P-256; see qureddy#817" >&2; exit 1; }
        '''
      }
    }

    stage('gates') {
      // The Justfile owns the gate definitions. Calling the recipes keeps this
      // pipeline from drifting into a second, weaker copy of them.
      steps {
        sh 'just lint'
        sh 'just format-check'
        sh 'just typecheck'
      }
    }

    stage('unit') {
      steps {
        sh "uv run --locked pytest tests --ignore=tests/live --ignore=tests/ike_lab " +
           "--cov=qureddy --cov-fail-under=90 -q --junitxml=${REPORT_DIR}/unit.xml"
      }
    }

    stage('live: badssl cipher ratings') {
      environment {
        QUREDDY_LEGACY_OPENSSL = "${LEGACY_OPENSSL}"
      }
      steps {
        sh "uv run --locked pytest tests/live/test_live_badssl_ciphers.py -q --junitxml=${REPORT_DIR}/badssl.xml"
      }
    }

    stage('live: canonical targets') {
      steps {
        sh "uv run --locked pytest tests/live/test_live_targets.py -q --junitxml=${REPORT_DIR}/live.xml"
      }
    }

    stage('no skipped tests') {
      // A skipped test reports as a pass in most summaries. The badssl stages skip
      // themselves when the compatibility runtime is absent, which is the one way
      // this pipeline could go green while asserting nothing.
      steps {
        sh '''
          set -eu
          skipped=$(grep -ho 'skipped="[0-9]*"' "$REPORT_DIR"/*.xml \\
                    | grep -o '[0-9]*' | paste -sd+ - | bc)
          echo "skipped tests: ${skipped:-0}"
          [ "${skipped:-0}" -eq 0 ] || { echo "a test was skipped; see the reports" >&2; exit 1; }
        '''
      }
    }
  }

  post {
    always {
      junit allowEmptyResults: false, testResults: "${REPORT_DIR}/*.xml"
      archiveArtifacts artifacts: "${REPORT_DIR}/*.xml", allowEmptyArchive: false
    }
  }
}

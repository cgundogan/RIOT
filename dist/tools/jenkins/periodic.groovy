#!/usr/bin/env groovy

properties([[$class: 'BuildDiscarderProperty',
             strategy: [$class: 'LogRotator', numToKeepStr: '7']],
             pipelineTriggers([cron('H 0 * * *')]),
])

def common = evaluate readTrusted('dist/tools/jenkins/common.groovy')

def boards = []
def examples = []
def tests = []
def driver_tests = []
def pkg_tests = []
def periph_tests = []
def other_tests = []
def unittests = []

stage('setup') {
    node ('master') {
        sh '(( "\${RIOT_MIRROR}" )) && git -C "\${RIOT_MIRROR_DIR}" fetch --all'

        deleteDir()

        common.fetchBranch("--depth=1", "master:master ${env.BRANCH_NAME}", env.BRANCH_NAME)

        /* get all boards */
        boards = common.getBoards()

        /* get all examples */
        examples = common.getExamples()

        /* get all tests */
        tests = common.getTests()

        /* split tests into smaller sets */
        for (int i=0; i < tests.size(); i++) {
            if (tests[i].startsWith("tests/driver_")) {
                driver_tests << tests[i]
            }
            else if (tests[i].startsWith("tests/pkg_")) {
                pkg_tests << tests[i]
            }
            else if (tests[i].startsWith("tests/periph_")) {
                periph_tests << tests[i]
            }
            else if (tests[i].startsWith("tests/unittests")) {
                unittests << tests[i]
            }
            else {
                other_tests << tests[i]
            }
        }

        deleteDir()
    }
}

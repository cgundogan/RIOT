#!/usr/bin/env groovy

def common = evaluate readTrusted('dist/tools/jenkins/common.groovy')

def boards = []
def examples = []
def tests = []
def refSpecRemote = "pull/${env.CHANGE_ID}/merge"
def refSpecLocal = "pull_${env.CHANGE_ID}"

stage('setup') {
    node ('master') {
        common.stageSetup(boards, examples, tests, refSpecRemote, refSpecLocal)
        deleteDir()
    }
}

stage('static-tests') {
    common.stageStaticTests("master:master " + refSpecRemote, refSpecLocal)
}

stage("unittests") {
    common.stageUnitTests(boards, refSpecRemote, refSpecLocal)
}

stage("tests") {
    common.stageTests(boards, driver_tests, periph_tests, pkg_tests, other_tests, refSpecRemote, refSpecLocal)
}

stage("examples") {
    common.stageExamples(boards, examples, refSpecRemote, refSpecLocal)
}

if (currentBuild.result == null) {
    currentBuild.result = 'SUCCESS'
}

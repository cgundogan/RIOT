#!/usr/bin/env groovy

properties([[$class: 'BuildDiscarderProperty',
             strategy: [$class: 'LogRotator', numToKeepStr: '7']],
             pipelineTriggers([cron('H H(0-2) * * *')]),
])

def common = evaluate readTrusted('dist/tools/jenkins/common.groovy')

def boards = []
def examples = []
def tests = []
def refSpecRemote = env.BRANCH_NAME
def refSpecLocal = env.BRANCH_NAME

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
    common.stageTests(boards, tests, refSpecRemote, refSpecLocal)
}

stage("examples") {
    common.stageExamples(boards, examples, refSpecRemote, refSpecLocal)
}

if (currentBuild.result == null) {
    currentBuild.result = 'SUCCESS'
}

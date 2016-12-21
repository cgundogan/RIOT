#!/usr/bin/env groovy

def boards = [:]

stage('setup') {
    node ('master') {
        checkout scm
        stash 'sources'
        boards = sh(returnStdout: true, script: 'find $(pwd)/boards/* -maxdepth 0 -type d \\! -name "*-common" -exec basename {} \\; | tr "\\n" " "').trim().split(' ')
    }
}

stage('static-tests') {
    node('master') {
        unstash 'sources'
        def ret = sh(returnStatus: true, script: "declare -i RESULT=0; ./dist/tools/static-tests.sh >> success_static-tests.log 2>&1 || RESULT=1; " +
                                                 "if ((\$RESULT)); then mv success_static-tests.log error_static-tests.log; fi; exit \$RESULT")
        if (ret) {
            currentBuild.result = 'FAILURE'
        }
        step([$class: 'ArtifactArchiver', artifacts: "*_static-tests.log", fingerprint: true])
    }
}

stage("tests") {
    def builds = [:]

    def boardName = ""
    for (int i=0; i < boards.size(); i++) {
        boardName = boards[i]
        builds['linux_tests_' + boardName] = make_build("linux && boards && native", boardName, "default", "tests")
        builds['linux_examples_' + boardName] = make_build("linux && boards && native", boardName, "default", "examples")
    }

    builds['macOS_tests_native'] = make_build("macOS && native", "native", "macOS", "tests")
    builds['raspi_tests_native'] = make_build("raspi && native", "native", "raspi", "tests")

    builds['macOS_examples_native'] = make_build("macOS && native", "native", "macOS", "examples")
    builds['raspi_examples_native'] = make_build("raspi && native", "native", "raspi", "examples")

    parallel (builds)
}

def make_build(label, board, desc, arg)
{
    return {
        node(label) {
            unstash 'sources'
            def build_dir = pwd()
            try {
                timestamps {
                    echo "building ${arg} for ${board} on nodes with ${label}"
                    withEnv([
                      "BOARD=${board}",
                      "GIT_CACHE_DIR=/opt/jenkins/gitcache",
                      "CCACHE_BASEDIR=${build_dir}",
                      "CCACHE_DIR=/opt/jenkins/ccache/",
                      "GIT_CACHE_AUTOADD=1",
                      "RIOT_CI_BUILD=1"]) {
                        def ret = sh(returnStatus: true, script: "declare -i RESULT=0; for app in \$(find ${arg}/* -maxdepth 1 -name Makefile -print0 | xargs -0 -n1 dirname); do " +
                                  "if [[ \$(make -sC \$app info-boards-supported | tr ' ' '\n' | sed -n '/^${board}\$/p') ]]; then " +
                                  "echo \"\n\nBuilding \$app for ${board}\" >> success_${board}_${arg}_${desc}.log; "+
                                  "make -j\${NPROC} -C \$app all >> success_${board}_${arg}_${desc}.log 2>&1 || RESULT=1; " +
                                  "fi; done; if ((\$RESULT)); then mv success_${board}_${arg}_${desc}.log error_${board}_${arg}_${desc}.log; fi; exit \$RESULT")
                        if (ret) {
                            currentBuild.result = 'FAILURE'
                        }
                        step([$class: 'ArtifactArchiver', artifacts: "*_${board}_${arg}_${desc}.log", fingerprint: true])
                    }
                }
            }  catch(e) {
                echo "!! FAILED !!\n${e.toString()}"
                currentBuild.result = 'FAILURE'
            }
        }
    }
}

#!/usr/bin/env groovy

def fetchBranch(fetchArgs, refSpecRemote, refSpecLocal)
{
    sh """git init
    RIOT_MIRROR=0
    if (( "\${RIOT_MIRROR}" )); then RIOT_URL="\${RIOT_MIRROR_URL}"; else RIOT_URL="https://github.com/cgundogan/RIOT"; fi
    git remote add origin "\${RIOT_URL}"
    for RETRIES in {1..3}; do
        timeout 30 git fetch -u -n ${fetchArgs} origin ${refSpecRemote}:${refSpecLocal} && break
    done
    [[ "\$RETRIES" -eq 3 ]] && exit 1
    git checkout ${refSpecLocal}"""
}

def stageSetup(boards, examples, tests, refSpecRemote, refSpecLocal)
{
    node ('master') {
        sh '(( "\${RIOT_MIRROR}" )) && git -C "\${RIOT_MIRROR_DIR}" fetch --all'

        deleteDir()

        fetchBranch("--depth=1", refSpecRemote, refSpecLocal)

        /* get all boards */
        boards.addAll(sh(returnStdout: true,
                         script: 'find $(pwd)/boards/* -maxdepth 0 -type d \\! -name "*-common" -exec basename {} \\;'
                        ).trim().split('\n'))

        /* get all examples */
        examples.addAll(sh(returnStdout: true,
                           script: 'find examples/* -maxdepth 1 -name Makefile -print0 | xargs -0 -n1 dirname'
                          ).trim().split('\n'))

        /* get all tests */
        tests.addAll(sh(returnStdout: true,
                        script: 'find tests/* -maxdepth 1 -name Makefile -print0 | xargs -0 -n1 dirname'
                       ).trim().split('\n'))
        deleteDir()
    }
}

def stageStaticTests(refSpecRemote, refSpecLocal)
{
    node('linux && boards') {
        deleteDir()

        fetchBranch("", refSpecRemote, refSpecLocal)

        def ret = sh(returnStatus: true,
                     script: """#!/bin/bash +x
                                declare -i RESULT=0
                                ./dist/tools/static-tests.sh >> success_static-tests.log 2>&1 || RESULT=1
                                if ((\$RESULT)); then
                                    mv success_static-tests.log error_static-tests.log;
                                fi;
                                exit \$RESULT""")
        if (ret) {
            currentBuild.result = 'UNSTABLE'
        }

        step([$class: 'ArtifactArchiver', artifacts: "*_static-tests.log", fingerprint: true, allowEmptyArchive: true])

        deleteDir()
    }
}

def stageUnitTests(boards, refSpecRemote, refSpecLocal)
{
    def builds = [:]
    def unittests = []

    unittests << "tests/unittests"

    /* setup all concurrent builds */
    def boardName = ""
    for (int i=0; i < boards.size(); i++) {
        boardName = boards[i]
        builds['linux_unittests_' + boardName] = make_build("linux && boards && native", boardName, "linux_unittests", unittests, refSpecRemote, refSpecLocal)
    }
    /* distribute all builds to the slaves */
    parallel (builds)

    abortOnError("unittests failed")
}

def stageTests(boards, tests, refSpecRemote, refSpecLocal)
{
    def driver_tests = []
    def pkg_tests = []
    def periph_tests = []
    def other_tests = []
    def builds = [:]

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
            continue
        }
        else {
            other_tests << tests[i]
        }
    }


    /* setup all concurrent builds */
    def boardName = ""
    for (int i=0; i < boards.size(); i++) {
        boardName = boards[i]
        builds['linux_driver_tests_' + boardName] = make_build("linux && boards && native", boardName, "linux_driver_tests", driver_tests, refSpecRemote, refSpecLocal)
        builds['linux_pkg_tests_' + boardName] = make_build("linux && boards && native", boardName, "linux_pkg_tests", pkg_tests, refSpecRemote, refSpecLocal)
        builds['linux_periph_tests_' + boardName] = make_build("linux && boards && native", boardName, "linux_periph_tests", periph_tests, refSpecRemote, refSpecLocal)
        builds['linux_other_tests_' + boardName] = make_build("linux && boards && native", boardName, "linux_other_tests", other_tests, refSpecRemote, refSpecLocal)
    }


/*  ignore macOS builds for now - macOS is currently broken for native
    builds['macOS_driver_tests_native'] = make_build("macOS && native", "native", "macOS_driver_tests", driver_tests)
    builds['macOS_pkg_tests_native'] = make_build("macOS && native", "native", "macOS_pkg_tests", pkg_tests)
    builds['macOS_periph_tests_native'] = make_build("macOS && native", "native", "macOS_periph_tests", periph_tests)
    builds['macOS_other_tests_native'] = make_build("macOS && native", "native", "macOS_other_tests", other_tests)
*/
/*  ignore raspi builds for now - slows down the build (needs investigation)
    builds['raspi_driver_tests_native'] = make_build("raspi && native", "native", "raspi_driver_tests", driver_tests)
    builds['raspi_pkg_tests_native'] = make_build("raspi && native", "native", "raspi_pkg_tests", pkg_tests)
    builds['raspi_periph_tests_native'] = make_build("raspi && native", "native", "raspi_periph_tests", periph_tests)
    builds['raspi_other_tests_native'] = make_build("raspi && native", "native", "raspi_other_tests", other_tests)
*/

    /* distribute all builds to the slaves */
    parallel (builds)

    abortOnError("tests failed")
}

def stageExamples(boards, examples, refSpecRemote, refSpecLocal)
{
    def builds = [:]

    /* setup all concurrent builds */
    def boardName = ""
    for (int i=0; i < boards.size(); i++) {
        boardName = boards[i]
        builds['linux_examples_' + boardName] = make_build("linux && boards && native", boardName, "linux_examples", examples, refSpecRemote, refSpecLocal)
    }

/*  ignore macOS builds for now - macOS is currently broken for native
    builds['macOS_examples_native'] = make_build("macOS && native", "native", "macOS_examples", examples)
*/
/*  ignore raspi builds for now - slows down the build (needs investigation)
    builds['raspi_examples_native'] = make_build("raspi && native", "native", "raspi_examples", examples)
*/

    /* distribute all builds to the slaves */
    parallel (builds)

    abortOnError("examples failed")
}

def abortOnError(msg)
{
    if ((currentBuild.result != null) && (currentBuild.result == 'FAILURE')) {
        error msg
    }
}

def make_build(label, board, desc, arg, refSpecRemote, refSpecLocal)
{
    return {
        node(label) {
            try {
                deleteDir()
                fetchBranch("--depth=1", refSpecRemote, refSpecLocal)
                sh "./dist/tools/git/git-cache init"
                timestamps {
                    def apps = arg.join(' ')
                    echo "building ${apps} for ${board} on nodes with ${label}"
                    withEnv(["BOARD=${board}", "CCACHE_BASEDIR=" + pwd(), "RIOT_CI_BUILD=1"]) {
                        def ret = sh(returnStatus: true,
                                     script: """#!/bin/bash +ex
                                                declare -i RESULT=0
                                                for app in ${apps}; do
                                                    if [[ \$(make -sC \$app info-boards-supported | tr ' ' '\n' | sed -n '/^${board}\$/p') ]]; then
                                                        echo \"\n\nBuilding \$app for ${board}\" >> success_${board}_${desc}.log
                                                        rm -rf jenkins_bin; mkdir jenkins_bin
                                                        CFLAGS_DBG=\"\" BINDIR=\$(pwd)/jenkins_bin make -j\${NPROC} -C \$app all >> success_${board}_${desc}.log 2>&1 || RESULT=1
                                                    fi;
                                                done;
                                                if ((\$RESULT)); then
                                                    mv success_${board}_${desc}.log error_${board}_${desc}.log
                                                fi;
                                                exit \$RESULT""")
                        if (ret) {
                            currentBuild.result = 'FAILURE'
                        }
                        step([$class: 'ArtifactArchiver', artifacts: "*_${board}_${desc}.log", fingerprint: true, allowEmptyArchive: true])
                    }
                }
            }  catch(e) {
                echo "${e.toString()}"
                currentBuild.result = 'FAILURE'
            } finally {
                deleteDir()
            }
        }
    }
}

return this

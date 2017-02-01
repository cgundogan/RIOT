#!/usr/bin/env groovy

def getBoards()
{
    return sh(returnStdout: true,
              script: 'find $(pwd)/boards/* -maxdepth 0 -type d \\! -name "*-common" -exec basename {} \\;'
           ).trim().split('\n')
}

def getExamples()
{
    return sh(returnStdout: true,
               script: 'find examples/* -maxdepth 1 -name Makefile -print0 | xargs -0 -n1 dirname'
           ).trim().split('\n')
}

def getTests()
{
    return sh(returnStdout: true,
              script: 'find tests/* -maxdepth 1 -name Makefile -print0 | xargs -0 -n1 dirname'
           ).trim().split('\n')
}

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

return this

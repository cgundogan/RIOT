#!/usr/bin/env groovy

/* stop running jobs */
abortPreviousBuilds()

def jobName = env.JOB_NAME.split("/")[0]

if (jobName == "RIOT_PR") {
    evaluate readTrusted('dist/tools/jenkins/pr.groovy')
}
else {
    evaluate readTrusted('dist/tools/jenkins/periodic.groovy')
}

/* abort previous, running builds */
def abortPreviousBuilds()
{
    def buildnum = env.BUILD_NUMBER.toInteger()
    def job = Jenkins.instance.getItemByFullName(env.JOB_NAME)
    for (build in job.builds) {
        if (!build.isBuilding() || (buildnum == build.getNumber().toInteger())) {
            continue;
        }
        build.doStop();
    }
}

import groovy.json.JsonOutput
import groovy.json.JsonSlurper

// File Environment
def fileProjectName = 'OZ-io-insecure-bank'
def fileBranchName = 'master'

// IO Environment
def ioPOCId = 'io-poc-demo'
def ioProjectName = 'OZ-io-insecure-bank'
def ioWorkflowEngineVersion = '2022.7.2'
def ioServerURL = 'https://io.codedx.synopsys.com/'
def ioRunAPI = '/api/ioiq/api/orchestration/runs/'

// SCM - GitHub
def gitHubOwner = 'OzViper'
def scmBranch = fileBranchName
def scmRepoName = 'insecure-bank'
def scmRevisionDate = ''

// AST - Polaris
def polarisProjectName = fileProjectName
def polarisBranchName = fileBranchName

// AST - Black Duck
def blackDuckURL = "https://testing.blackduck.synopsys.com"
def blackDuckProjectName = fileProjectName
def blackDuckProjectVersion = fileBranchName

// BTS Configuration
def jiraAssignee = 'SIG User'
def jiraIssueQuery = 'resolution=Unresolved'
def jiraProjectKey = 'IO_Demo'
def jiraProjectName = 'IODEMO'

// Code Dx Configuration
def codeDxProjectId = '137'
def codeDxInstnceURL = "https://demo.codedx.synopsys.com/codedx"
def codeDxProjectAPI = "/api/projects/"
def codeDxAnalysisEndpoint = "/analysis"
def codeDxProjectContext = "${codeDxProjectId};branch=${fileBranchName}"
def codeDxBranchAnalysisAPI = codeDxInstnceURL + codeDxProjectAPI + codeDxProjectId + codeDxAnalysisEndpoint

// Notification Configuration
def slackConfigName = ''
def msTeamsConfigName = ''

// IO Prescription Placeholders
def runId
def isSASTEnabled
def isSASTPlusMEnabled
def isSCAEnabled
def isDASTEnabled
def isDASTPlusMEnabled
def isImageScanEnabled
def isNetworkScanEnabled
def isCloudReviewEnabled
def isThreatModelEnabled
def isInfraReviewEnabled
def breakBuild


pipeline {
    agent any

    environment {
        gitHubPOCId = credentials('OZ_GITHUB_TOKEN')
        polarisConfigName = credentials('polaris-token')
        blackDuckPOCId = credentials('BlackDuck-AuthToken')
        jiraConfigName = credentials('DEMO_JIRA_TOKEN')
        IO_ACCESS_TOKEN = credentials("${IO-AUTH-TOKEN}")
        CODEDX_ACCESS_TOKEN = credentials("${CODEDX_API_KEY}")
    }
    
    tools {
        maven 'maven-3'
    }

    stages {
        
        stage('Build') {
            steps {
                echo "mvn clean compile"
            }
        }

        // Get prescription from IO
        stage('Prescription') {
            
            steps {
                synopsysIO(connectors: [
                    io(
                        configName: ioPOCId,
                        projectName: ioProjectName,
                        workflowVersion: ioWorkflowEngineVersion),
                    github(
                        branch: scmBranch,
                        configName: gitHubPOCId,
                        owner: gitHubOwner,
                        repositoryName: scmRepoName),
                    jira(
                        assignee: jiraAssignee,
                        configName: jiraConfigName,
                        issueQuery: jiraIssueQuery,
                        projectKey: jiraProjectKey,
                        projectName: jiraProjectName)
                    ]) {
                        sh 'io --stage io'
                    }

                script {
                    // IO-IQ will write the prescription to io_state JSON
                    if (fileExists('io_state.json')) {
                        def prescriptionJSON = readJSON file: 'io_state.json'

                        // Pretty-print Prescription JSON
                        // def prescriptionJSONFormat = JsonOutput.toJson(prescriptionJSON)
                        // prettyJSON = JsonOutput.prettyPrint(prescriptionJSONFormat)
                        // echo("${prettyJSON}")

                        // Use the run Id from IO IQ to get detailed message/explanation on prescription
                        runId = prescriptionJSON.data.io.run.id
                        def apiURL = ioServerURL + ioRunAPI + runId
                        def res = sh(script: "curl --location --request GET ${apiURL} --header 'Authorization: Bearer ${IO_ACCESS_TOKEN}'", returnStdout: true)

                        def jsonSlurper = new JsonSlurper()
                        def ioRunJSON = jsonSlurper.parseText(res)
                        def ioRunJSONFormat = JsonOutput.toJson(ioRunJSON)
                        def ioRunJSONPretty = JsonOutput.prettyPrint(ioRunJSONFormat)
                        print("==================== IO-IQ Explanation ======================")
                        echo("${ioRunJSONPretty}")
                        print("==================== IO-IQ Explanation ======================")

                        // Update security flags based on prescription
                        isSASTEnabled = prescriptionJSON.data.prescription.security.activities.sast.enabled
                        isSASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.sastPlusM.enabled
                        isSCAEnabled = prescriptionJSON.data.prescription.security.activities.sca.enabled
                        isDASTEnabled = prescriptionJSON.data.prescription.security.activities.dast.enabled
                        isDASTPlusMEnabled = prescriptionJSON.data.prescription.security.activities.dastPlusM.enabled
                        isImageScanEnabled = prescriptionJSON.data.prescription.security.activities.imageScan.enabled
                        isNetworkScanEnabled = prescriptionJSON.data.prescription.security.activities.NETWORK.enabled
                        isCloudReviewEnabled = prescriptionJSON.data.prescription.security.activities.CLOUD.enabled
                        isThreatModelEnabled = prescriptionJSON.data.prescription.security.activities.THREATMODEL.enabled
                        isInfraReviewEnabled = prescriptionJSON.data.prescription.security.activities.INFRA.enabled
                    } else {
                        error('IO prescription JSON not found.')
                    }
                }
            }
        }

        // SAST
        stage('SAST') {
            when {
                expression { isSASTEnabled }
            }
            steps {
                echo 'Running SAST using Polaris'
                synopsysIO(connectors: [
                    polaris(
                        configName: polarisConfigName, 
                        projectName: polarisProjectName,
                        branchName: polarisBranchName)]) {
                            sh 'io --stage execution --state io_state.json'
                }
            }
        }

        // SCA
        stage('SCA') {
            when {
                expression { isSCAEnabled }
            }
            steps {
                echo 'Running SCA using BlackDuck'
                synopsysIO(connectors: [
                    blackduck(
                        configName: blackDuckPOCId,
                        projectName: blackDuckProjectName,
                        projectVersion: blackDuckProjectVersion)]) {
                            sh 'io --stage execution --state io_state.json'
                }
            }
        }

        // Manual SAST Stage
        stage('SAST+M') {
            when {
                expression { isSASTPlusMEnabled }
            }
            steps {
                input message: 'High risk score or significant code-change detected. Perform manual secure code-review.'
            }
        }

        // Run IO's Workflow Engine
        stage('Workflow') {
            
            steps {
                script {
                    print("========================== Code Dx Branch Analysis ============================")
                    def res = sh(script: "curl --location --request POST ${codeDxBranchAnalysisAPI} --header 'Authorization: Bearer ${CODEDX_ACCESS_TOKEN}' --form 'filenames=\"\"' --form 'includeGitSource=\"\"' --form 'gitBranchName=\"\"' --form 'branchName=${fileBranchName}'", returnStdout: true)
                    echo("${res}")
                    print("========================== Code Dx Branch Analysis ============================")
                }
                synopsysIO(connectors: [
                 /*   slack(configName: slackConfigName),
                    msteams(configName: msTeamsConfigName)*/ ]) {
                        sh 'io --stage workflow --state io_state.json' 
               } 
            }
        } 

        // Security Sign-Off Stage
        stage('Security') {
            steps {
                script {
                    if (fileExists('wf-output.json')) {
                        def wfJSON = readJSON file: 'wf-output.json'

                        // If the Workflow Output JSON has a lot of key-values; Jenkins throws a StackOverflow Exception
                        //  when trying to pretty-print the JSON
                        // def wfJSONFormat = JsonOutput.toJson(wfJSON)
                        // def wfJSONPretty = JsonOutput.prettyPrint(wfJSONFormat)
                        // print("======================== IO Workflow Engine Summary ==========================")
                        // print(wfJSONPretty)
                        // print("======================== IO Workflow Engine Summary ==========================")

                        breakBuild = wfJSON.breaker.status
                        print("========================== Build Breaker Status ============================")
                        print("Breaker Status: $breakBuild")
                        print("========================== Build Breaker Status ============================")

                        if (breakBuild) {
                            input message: 'Build-breaker criteria met.'
                        }
                    } else {
                        print('No output from the Workflow Engine. No sign-off required.')
                    }
                }
            }
        }
    }

    post {
        always {
            // Archive Results/Logs
            // archiveArtifacts artifacts: '**/*-results*.json', allowEmptyArchive: 'true'

            script {
                // Remove the state json file as it has sensitive information
                if (fileExists('io_state.json')) {
                    sh 'rm io_state.json'
                }
            }
        }
    }
}

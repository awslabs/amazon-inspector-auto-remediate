import boto3
import json
import logging
import datetime

ssm = boto3.client('ssm')
inspector = boto3.client('inspector')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# quick function to handle datetime serialization problems
enco = lambda obj: (
    obj.isoformat()
    if isinstance(obj, datetime.datetime)
    or isinstance(obj, datetime.date)
    else None
)

def lambda_handler(event, context):

    logger.debug('Raw Lambda event:')
    logger.debug(event)

    # extract the message that Inspector sent via SNS
    message = event['Records'][0]['Sns']['Message']
    logger.debug('Event from SNS: ' + message)
    
    # get inspector notification type
    notificationType = json.loads(message)['event']
    logger.info('Inspector SNS message type: ' + notificationType)

    # skip everything except report_finding notifications
    if notificationType != "FINDING_REPORTED":
        logger.info('Skipping notification that is not a new finding: ' + notificationType)
        return 1
    
    # extract finding ARN
    findingArn = json.loads(message)['finding']
    logger.info('Finding ARN: ' + findingArn)

    # get finding and extract detail
    response = inspector.describe_findings(findingArns = [ findingArn ], locale='EN_US')
    logger.debug('Inspector DescribeFindings response:')
    logger.debug(response)
    finding = response['findings'][0]
    logger.debug('Raw finding:')
    logger.debug(finding)
   

    # skip uninteresting findings
    title = finding['title']
    logger.debug('Finding title: ' + title)

    if title == "Unsupported Operating System or Version":
        logger.info('Skipping finding: ' + title)
        return 1
        
    if title == "No potential security issues found":
        logger.info('Skipping finding: ' + title)
        return 1
    
    service = finding['service']
    logger.debug('Service: ' + service)
    if service != "Inspector":
        logger.info('Skipping finding from service: ' + service)
        return 1
    
    cveId = ""
    for attribute in finding['attributes']:
        if attribute['key'] == "CVE_ID":
            cveId = attribute['value']
            break
    logger.info('CVE ID: ' + cveId)
    
    if cveId == "":
        logger.info('Skipping non-CVE finding (could not find CVE ID)')
        return 1
    
    assetType = finding['assetType']
    logger.debug('Asset type: ' + assetType)
    if assetType != "ec2-instance":
        logger.info('Skipping non-EC2-instance asset type: ' + assetType)
        return 1
  
    instanceId = finding['assetAttributes']['agentId']
    logger.info('Instance ID: ' + instanceId)
    if not instanceId.startswith("i-"):
        logger.info('Invalid instance ID: ' + instanceId)
        return 1
        
    # if we got here, we have a valid CVE type finding for an EC2 instance with a well-formed instance ID
    
    # query SSM for information about this instance
    filterList = [ { 'key': 'InstanceIds', 'valueSet': [ instanceId ] } ]
    response = ssm.describe_instance_information( InstanceInformationFilterList = filterList, MaxResults = 50 )
    logger.debug('SSM DescribeInstanceInformation response:')
    logger.debug(response)
    instanceInfo = response['InstanceInformationList'][0]
    logger.debug('Instance information:')
    logger.debug(instanceInfo)
    pingStatus = instanceInfo['PingStatus']
    logger.info('SSM status of instance: ' + pingStatus)
    lastPingTime = instanceInfo['LastPingDateTime']
    logger.debug('SSM last contact:')
    logger.debug(lastPingTime)
    agentVersion = instanceInfo['AgentVersion']
    logger.debug('SSM agent version: ' + agentVersion)
    platformType = instanceInfo['PlatformType']
    logger.info('OS type: ' + platformType)
    osName = instanceInfo['PlatformName']
    logger.info('OS name: ' + osName)
    osVersion = instanceInfo['PlatformVersion']
    logger.info('OS version: ' + osVersion)
    
    # Terminate if SSM agent is offline
    if pingStatus != 'Online':
        logger.info('SSM agent for this instance is not online: ' + pingStatus)
        return 1
    
    # This script only supports remediation on Linux
    if platformType != "Linux":
        logger.info('Skipping non-Linux platform: ' + platformType)
        return 1
        
    # Look up the correct command to update this Linux distro
    # to-do: patch only CVEs, or patch only the specific CVE
    if osName == 'Ubuntu':
        commandLine = "apt-get update -qq -y; apt-get upgrade -y"
    elif osName == 'Amazon Linux AMI':
        commandLine = "yum update -q -y; yum upgrade -y"
    else:
        logger.info('Unsupported Linux distribution: ' + osName)
        return 1
    logger.info('Command line to execute: ' + commandLine)
    
    # now we SSM run-command
    response = ssm.send_command(
        InstanceIds = [ instanceId ],
        DocumentName = 'AWS-RunShellScript',
        Comment = 'Lambda function performing Inspector CVE finding auto-remediation',
        Parameters = { 'commands': [ commandLine ] }
        )
    
    logger.info('SSM send-command response:')
    logger.info(response)

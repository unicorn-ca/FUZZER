import boto3
import requests
from hypothesis import given, assume, settings, HealthCheck, Verbosity, strategies as st
from datetime import timedelta


def read_payload():
    with open("FUZZDB_Postgres_Enumeration.txt",'r') as infile:
        blns = infile.readlines()
    return blns

def pipeline_status(job, success, details={}):
    cp_client = boto3.client('codepipeline')
    if success:
        cp_client.put_job_success_result(jobId=job)
    else:
        cp_client.put_job_failure_result(jobId=job, failureDetails=details)

APIENDPOINT_OUTPUT_KEY = 'ServiceEndpoint'
SNOOPER_ROLE = 'arn:aws:iam::171350118496:role/unicorn-xaccount-cfm-stack-snooper'
def get_account_client(client, account):
    print(f"Obtaining STS token for {account}")
    sts_client = boto3.client('sts')
    creds = sts_client.assume_role(
        RoleArn=SNOOPER_ROLE,
        RoleSessionName='temp-chen-lambda-access',
        DurationSeconds=900
    )
    
    print(f"Starting {client} on cross-account session")
    sess = boto3.session.Session(aws_access_key_id=creds['Credentials']['AccessKeyId'],
                                 aws_secret_access_key=creds['Credentials']['SecretAccessKey'],
                                 aws_session_token=creds['Credentials']['SessionToken'])
    return sess.client(client)
    

def get_stack_api_endpoint(stack_name):
    client = get_account_client('cloudformation', 'dev')
    stack = client.describe_stacks(StackName=stack_name)

    if len(stack['Stacks']) > 1:
        print('Warning', 'Found more than one stack, taking [0]')

    stack = stack['Stacks'][0]
    if stack['StackStatus'] != 'CREATE_COMPLETE' and stack['StackStatus'] != 'UPDATE_COMPLETE':
        raise Exception('Stack is not ready')

    for output in stack['Outputs']:
        if output['OutputKey'] == APIENDPOINT_OUTPUT_KEY:
            return output['OutputValue']
    else:
        raise Exception(f'Did not find "{APIENDPOINT_OUTPUT_KEY}" output')

def handler(event, context):
    job_id = event['CodePipeline.job']['id']
    print(f"Starting job {job_id}")
    stack_name = event['CodePipeline.job']['data']['actionConfiguration']['configuration']['UserParameters']
    api_endpoint = get_stack_api_endpoint(stack_name)
    print(f"Fetched {api_endpoint} from {stack_name}")

    # falsification set not provided, need to produce generate for sql
    # very basic example for rest api from https://hypothesis.readthedocs.io/en/latest/examples.html
    @settings(verbosity=Verbosity.verbose, deadline=timedelta(seconds=15), max_examples=15)
    # composite strategies, draw from total corpus of vulnerabilities
    @given(st.sampled_from(read_payload()))
    def fuzz(s):
        #params = {'vuln-string': vuln}
        print(type(s))
        # add dymanic get from lambda api gateway endpoints, sign with IAM secret key for api gateway
        response = requests.get("https://vtvmemmfce.execute-api.us-east-2.amazonaws.com/dev",params=s)
        print(f"https status is {response.json()}")

        if response.ok:
            r = response.json()
            if 'result' in r:
                if r['result'] == "None":
                    pipeline_status(job_id, True)
                else:
                    pipeline_status(job_id, False, details={
                        'type': 'JobFailed',
                        'message': f"Failed test {s}"
                    })
        else:
            # Dubious decision
            pipeline_status(job_id, False, details={
                'type': 'JobFailed',
                'message': f"Failed test {s} - expected 2xx, got {response.status_code}"
            })

    print("Starting Tests")
    ret = fuzz()
    pipeline_status(job_id, True)
    return ret


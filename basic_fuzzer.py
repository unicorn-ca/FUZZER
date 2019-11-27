import boto3
import requests
from hypothesis import given, assume, settings, HealthCheck, Verbosity, strategies as st
from datetime import timedelta
import urllib.parse
import os
import random
import sys

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
    vuln_string = ["1' or (SELECT count(*) FROM generate_series(1, 10000000))='10000000' -- "]
    log_list=[]
    @settings(verbosity=Verbosity.verbose, deadline=timedelta(seconds=15), max_examples=15)
    @given(st.sampled_from([vuln_string])|st.emails())
    def fuzz_sqli(s):
            base_url = None
            params = {'vuln-string': s}
            log_list.append(f"Trying payload {params} using url {base_url}")
        # add dymanic get from lambda api gateway endpoints, sign with IAM secret key for api gateway
            response = requests.get(f"{base_url}/sqli_vuln",params=params)
            print(f"request made with {response.url} endpoint")
            print(f"https status is {response.json()}")
            if response.ok:
                r = response.json()
                if 'result' in r:
                    if r['result'] == "None" or len(r['result']==0):
                        pipeline_status(job_id, True)
                    else:
                        pipeline_status(job_id, False, details={
                            'type': 'JobFailed',
                            'message': f"Failed test {s}"
                        })
                        assert r['result'] == "None"
            else:
                # Dubious decision
                # just log output
                pipeline_status(job_id, False, details={
                    'type': 'JobFailed',
                    'message': f"Failed test {s} - expected 2xx, got {response.status_code}"
                })
            # asserts?
    print("Starting Tests")
    try:
        ret = fuzz_sqli()
    except (Exception,AssertionError) as e:
        print(f"Fuzzer failed with exception in execution {e}")
        pipeline_status(job_id, False, details={
    'type': 'JobFailed',
    'message': f"Failed test with assertion raised {e} - expected 2xx"
    })
    else:
        pipeline_status(job_id, True)
        s3 = boto3.client('s3')
        # bucket_name = os.environ['BUCKET_NAME'] # Supplied by Function service-discovery wire
        bucket_name = "fuzzerlambda"
        file_name = f"debug{random.randint(0,sys.maxsize)}.log"
        s3_path = "logs/" + file_name
        s3 = boto3.resource("s3")
        response=s3.Bucket(bucket_name).put_object(Key=s3_path, Body=str.encode("\n".join(log_list)))
        return ret

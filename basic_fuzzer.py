import boto3
import requests
from hypothesis import given, assume, settings, HealthCheck, Verbosity, strategies as st
from datetime import timedelta


def read_payload():
    with open("FUZZDB_Postgres_Enumeration.txt",'r') as infile:
        blns = infile.readlines()
    return blns

def pipeline_status(job, success):
    cp_client = boto3.client('codepipeline')
    if success:
        cp_client.put_job_success_result(jobId=job)
    else:
        cp_client.put_job_failure_result(jobId=job)

def handler(event, context):
    job_id = event['CodePipeline.job']['id']
    print(job_id)
    print(event['actionConfiguration']['configuration']['UserParameters'])

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

        if response.status_code == 200:
            if response.json()['result'] == "None":
                pipeline_status(job_id, True)
            else:
                pipeline_status(job_id, False)
        else:
            pipeline_status(job_id, False)

    return fuzz()


import requests
from hypothesis import given, assume, settings,HealthCheck,Verbosity, strategies as st
from datetime import timedelta

# add path vscode plugin
def readp():
    with open("payloads-sql-blind-MSSQL-INSERT.txt",'r') as infile:
        fun = infile.readlines()
    return fun

def readp2():
    with open("payload.txt",'r') as infile:
        run = infile.readlines()
    return run

def read_payload():
    with open("FUZZDB_Postgres_Enumeration.txt",'r') as infile:
        blns = infile.readlines()
    return blns

def handler(event, context):
    # falsification set not provided, need to produce generate for sql
    # very basic example for rest api from https://hypothesis.readthedocs.io/en/latest/examples.html
    @settings(verbosity=Verbosity.verbose,deadline=timedelta(seconds=100),max_examples=15)
    # composite strategies, draw from total corpus of vulnerabilities, positives
    @given(st.sampled_from(read_payload()+readp2()+readp()))
    def fuzz(s):
        #params = {'vuln-string': vuln}
        print(type(s))
        # add dymanic get from lambda api gateway endpoints, sign with IAM secret key for api gateway
        response = requests.get("https://vtvmemmfce.execute-api.us-east-2.amazonaws.com/dev",params=s)
        print(f"https status is {response.json()}")
        if response.status_code == 200:
            assert(response.json()['result']=="None")
            # enumeration attack assert null response for now
            # functional tests?
        fuzz()


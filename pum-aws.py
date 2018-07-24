#!/usr/bin/python
#

import sys
import boto3
import requests
import getpass
import configparser
import base64
import xml.etree.ElementTree as ET
import re
import os
from bs4 import BeautifulSoup
#import logging
#logging.basicConfig(level=logging.DEBUG)

# Variables
profile_region = 'eu-west-1'
profile_output = 'json'
sslverification = True
idpentryurl = 'https://federation.visma.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices'
tokenDuration = 60*60
credentials_path = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
config_path = os.path.join(os.path.expanduser("~"), ".aws", "config")

# Get the federated credentials from the user
print("Warning: This script will overwrite your default AWS credentials stored at "+credentials_path+"\n")
print("Privileged user (e.g. adm\dev_aly):", end=" ")
username = input()
password = getpass.getpass(prompt='Domain password: ')

# 1st HTTP request: GET the login form
session = requests.Session()
# Parse the response and extract all the necessary values
formresponse = session.get(idpentryurl, verify=sslverification, allow_redirects=True)
idpauthformsubmiturl = formresponse.url
formsoup = BeautifulSoup(formresponse.text, 'html.parser') #.decode('utf8')
payload = {}
for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name', '')
    value = inputtag.get('value', '')
    if "username" in name.lower():
        payload[name] = username
    elif "authmethod" in name.lower():
        payload[name] = "FormsAuthentication"
    elif "password" in name.lower():
        payload[name] = password
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# 2nd HTTP request: POST the username and password
response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification, allow_redirects=True)
#Get the challenge token from the user to pass to LinOTP (challengeQuestionInput)
print("Visma Google Auth 2FA Token:", end=" ")
token = input()
# Build nested data structure, parse the response and extract all the necessary values
tokensoup = BeautifulSoup(response.text, 'html.parser') #.decode('utf8')
payload = {}
for inputtag in tokensoup.find_all(re.compile('(INPUT|input)')):
    name = inputtag.get('name','')
    value = inputtag.get('value','')
    if "challenge" in name.lower():
        payload[name] = token
    elif "authmethod" in name.lower():
        payload[name] = "VismaMFAAdapter"
    else:
        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
        payload[name] = value

# 3rd HTTP request: POST the 2FA token
tokenresponse = session.post(response.url, data=payload, verify=sslverification, allow_redirects=True)

# Extract the SAML assertion and pass it to the AWS STS service
# Decode the response and extract the SAML assertion
soup = BeautifulSoup(tokenresponse.text, 'html.parser') #.decode('utf8')
assertion = ''
# Look for the SAMLResponse attribute of the input tag (determined by analyzing the debug print lines above)
for inputtag in soup.find_all('input'):
    if(inputtag.get('name') == 'SAMLResponse'):
        assertion = inputtag.get('value')
# Error handling, If ADFS does not return a SAML assertion response
if (assertion == ''):
    print('Your login failed, please contact launch control or check token/username/passwd')
    sys.exit(0)
# Parse the returned assertion and extract the authorized roles
awsroles = []
root = ET.fromstring(base64.b64decode(assertion))
for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
    if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
        for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
            awsroles.append(saml2attributevalue.text)
# Note the format of the attribute value should be role_arn,principal_arn
for awsrole in awsroles:
    chunks = awsrole.split(',')
    if'saml-provider' in chunks[0]:
        newawsrole = chunks[1] + ',' + chunks[0]
        index = awsroles.index(awsrole)
        awsroles.insert(index, newawsrole)
        awsroles.remove(awsrole)

# If user has more than one role, ask the user which one they want, otherwise just proceed
print("")
if len(awsroles) > 1:
    i = 0
    print("Please choose the AWS account and role you would like to assume:")
    for awsrole in awsroles:
        print('[', i, ']: ', awsrole.split(',')[0])
        i += 1
    print ("Selection:", end=" ")
    selectedroleindex = input()

    # Basic sanity check of input
    if int(selectedroleindex) > (len(awsroles) - 1):
        print('You selected an invalid role index, please try again')
        sys.exit(0)

    role_arn = awsroles[int(selectedroleindex)].split(',')[0]
    principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
else:
    role_arn = awsroles[0].split(',')[0]
    principal_arn = awsroles[0].split(',')[1]

# Use the assertion to get an AWS STS token using Assume Role with SAML
client = boto3.client('sts')
token = client.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = tokenDuration)

# Write the AWS STS token into the AWS credential file
credentials_config = configparser.RawConfigParser()
credentials_config.read(credentials_path)
if not credentials_config.has_section('default'):
    credentials_config.add_section('default')
credentials_config.set('default', 'aws_access_key_id', token['Credentials']['AccessKeyId'])
credentials_config.set('default', 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
credentials_config.set('default', 'aws_session_token', token['Credentials']['SessionToken'])
os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
with open(credentials_path, 'w') as configfile:
    credentials_config.write(configfile)
	
# Write the AWS config file
config_config = configparser.RawConfigParser()
config_config.read(config_path)
if not config_config.has_section('default'):
    config_config.add_section('default')
config_config.set('default', 'region', profile_region)
config_config.set('default', 'output', profile_output)
os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, 'w') as configfile:
    config_config.write(configfile)


# Give the user some basic info as to what has just happened
print('\n----------------------------------------------------------------')
print('Your AWS access key pair has been stored in the AWS configuration file {0}'.format(credentials_path))
print('Note that it will expire at {0}'.format(token['Credentials']['Expiration']))
print('Usage example: aws s3api list-buckets') #--profile default
print('----------------------------------------------------------------\n')

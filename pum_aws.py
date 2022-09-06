#!/usr/bin/env python
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
import argparse
from bs4 import BeautifulSoup
#import logging
#logging.basicConfig(level=logging.DEBUG)

def setProfile(section, role_arn, principal_arn):
    try:
        token = client.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = tokenDuration)
    
        if not credentials_config.has_section(section):
            credentials_config.add_section(section)
        credentials_config.set(section, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
        credentials_config.set(section, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
        credentials_config.set(section, 'aws_session_token', token['Credentials']['SessionToken'])
        credentials_config.set(section, 'region', profile_region)
    except:
        print("Access denied to " + section)

def setConfig(section, region, output):
    # Write the AWS config file
    if section != "default":
        config_section="profile " + section
    else:
        config_section=section

    if not config_config.has_section(config_section):
        config_config.add_section(config_section)
    config_config.set(config_section, 'region', region)
    config_config.set(config_section, 'output', output)

# noinspection PyPackageRequirements
def main():
    # Variables
    profile_output = 'json'
    sslverification = True
    idpentryurl = 'https://federation.visma.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices'
    credentials_path = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
    config_path = os.path.join(os.path.expanduser("~"), ".aws", "config")
    pumaws_configpath = os.path.join(os.path.expanduser("~"), ".pum-aws")

    parser = argparse.ArgumentParser(description="Get temporary AWS credentials using Visma federated access with privileged users.")
    parser.add_argument("-p", "--profile", default="default", help="Store credentials for a non-default AWS profile (default: override default credentials)")
    parser.add_argument("-a", "--account", help="Filter roles for the given AWS account")
    parser.add_argument("-r", "--region", help="Configure profile for the specified AWS region (default: eu-west-1)", default="eu-west-1")
    parser.add_argument("-m", "--allprofiles", help="Fetch all profiles", default="0")
    parser.add_argument("-d", "--duration", help="Token duration time in hours (max: 3)", default="1")

    args = parser.parse_args()

    section=args.profile
    account=args.account
    fetch_allprofiles = int(args.allprofiles)

    global tokenDuration
    tokenDuration = int(args.duration)*60*60

    global profile_region
    profile_region = args.region

    # Read last used user name
    pumaws_config = configparser.RawConfigParser()
    pumaws_config.read(pumaws_configpath)
    lastuser = ""
    use_aliases = "false"
    if pumaws_config.has_section("default"):
        lastuser = pumaws_config.get("default", "username")
        if pumaws_config.has_option("default", "use_account_aliases"):
           use_aliases = pumaws_config.get("default", "use_account_aliases")

    # Get the federated credentials from the user
    print("Warning: This script will overwrite your AWS credentials stored at "+credentials_path+", section ["+section+"]\n")
    if lastuser != "":
        username = input("Privileged user (e.g. adm\dev_aly) [" + lastuser + "]: ")
    else:
        username = input("Privileged user (e.g. adm\dev_aly): ")

    if username == "":
        username = lastuser

    password = getpass.getpass(prompt='Domain password: ')

    # Save last used user name
    if lastuser != username and username is not None and username != "":
        if not pumaws_config.has_section("default"):
            pumaws_config.add_section("default")
        pumaws_config.set("default", 'username', username)
        with open(pumaws_configpath, 'w') as configfile:
            pumaws_config.write(configfile)

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
    global assertion
    assertion = ''
    # Look for the SAMLResponse attribute of the input tag (determined by analyzing the debug print lines above)
    for inputtag in soup.find_all('input'):
        if(inputtag.get('name') == 'SAMLResponse'):
            assertion = inputtag.get('value')
    # Error handling, If ADFS does not return a SAML assertion response
    if (assertion == ''):
        raise Exception('Your login failed, please contact launch control or check token/username/passwd')
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

    ## Filter roles based on the specified account
    if account is not None:
        awsroles = list(filter(lambda x: account in x, awsroles))

    # If user has more than one role, ask the user which one they want, otherwise just proceed
    awsroles.sort()
    print("")
    if len(awsroles) > 1:
        if fetch_allprofiles == 0:
            i = 0
            print("Please choose the AWS account and role you would like to assume:")
            for awsrole in awsroles:
                if use_aliases == "true" and pumaws_config.has_option("account-mapping",awsrole.split(',')[0].split(':')[4]):
                    print('[', i, ']: ', pumaws_config.get("account-mapping",awsrole.split(',')[0].split(':')[4]) , "=>" ,awsrole.split(',')[0].split('/')[-1])
                else:
                    print('[', i, ']: ', awsrole.split(',')[0])
                i += 1
            print ("Selection:", end=" ")
            selectedroleindex = input()

            # Basic sanity check of input
            if int(selectedroleindex) > (len(awsroles) - 1):
                raise Exception('You selected an invalid role index, please try again')

            role_arn = awsroles[int(selectedroleindex)].split(',')[0]
            principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    # Write the AWS STS token into the AWS credential file
    global credentials_config
    credentials_config = configparser.RawConfigParser()
    credentials_config.read(credentials_path)

    global config_config
    config_config = configparser.RawConfigParser()
    config_config.read(config_path)

    global client
    client = boto3.client('sts')

    if fetch_allprofiles == 1:
        for awsrole in awsroles:
            role_arn = awsrole.split(',')[0]
            principal_arn = awsrole.split(',')[1]
            section = awsrole.split(':role/')[1]
            section = re.split('\W+', section)[0]
            setProfile(section, role_arn, principal_arn)
            setConfig(section, profile_region, profile_output)
    else:
        setProfile(section, role_arn, principal_arn)
        setConfig(section, profile_region, profile_output)

    os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
    with open(credentials_path, 'w') as configfile:
        credentials_config.write(configfile)

    os.makedirs(os.path.dirname(config_path), exist_ok=True)
    with open(config_path, 'w') as configfile:
        config_config.write(configfile)


    # Give the user some basic info as to what has just happened
    print('\n----------------------------------------------------------------')
    print('Your AWS access key pair has been stored in the AWS configuration file {0}'.format(credentials_path))
    print('Note that it will expire at {0}'.format(token['Credentials']['Expiration']))
    print('----------------------------------------------------------------\n')

    return username, token['Credentials']['AccessKeyId'], token['Credentials']['SecretAccessKey'], token['Credentials']['SessionToken']


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)
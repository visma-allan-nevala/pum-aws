#!/usr/bin/env python
#

import datetime
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
from subprocess import check_output,CalledProcessError
import json
#import logging
#logging.basicConfig(level=logging.DEBUG)

def haveOnePassword(item_name):
    try:
        check_output(["op"])
        return True
    except:  # noqa: E722
        return False

def setProfile(section, role_arn, principal_arn):
    token = client.assume_role_with_saml(RoleArn = role_arn, PrincipalArn = principal_arn, SAMLAssertion = assertion, DurationSeconds = tokenDuration)
    try:
        if not credentials_config.has_section(section):
            credentials_config.add_section(section)
        credentials_config.set(section, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
        credentials_config.set(section, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
        credentials_config.set(section, 'aws_session_token', token['Credentials']['SessionToken'])
        credentials_config.set(section, 'region', profile_region)
        return token
    except:  # noqa: E722
        print(f"Access denied to {section}")

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
    try:
        implementation()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        exit(0)

def implementation():    
    # Variables
    username = None
    password = None
    otp = None
    profile_output = 'json'
    sslverification = True
    idpentryurl = 'https://federation.visma.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices'
    credentials_path = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
    config_path = os.path.join(os.path.expanduser("~"), ".aws", "config")
    pumaws_configpath = os.path.join(os.path.expanduser("~"), ".pum-aws")

    parser = argparse.ArgumentParser(description="Get temporary AWS credentials using Visma federated access with privileged users.")
    parser.add_argument("--role", help="Role name")
    parser.add_argument("-p", "--profile", default="default", help="Store credentials for a non-default AWS profile (default: override default credentials)")
    parser.add_argument("-a", "--account", help="Filter roles for the given AWS account")
    parser.add_argument("-r", "--region", help="Configure profile for the specified AWS region (default: eu-west-1)", default="eu-west-1")
    default_op_account = os.environ.get('PUM_OP_ACCOUNT', "visma")
    parser.add_argument("--op-account", help="Name of the 1Password account (default: '" + default_op_account + "')", default=default_op_account, dest="op_account")
    default_op_item_name = os.environ.get('PUM_OP_ITEM_NAME', "Federation ADM")
    parser.add_argument("--op-item", help="Name of the 1Password item (default: '" + default_op_item_name + "')", default=default_op_item_name, dest="op_item")
    parser.add_argument("-m", "--profiles", help="Fetch pre-defined profiles separated with ,", default="")
    parser.add_argument("-d", "--duration", help="Token duration time in hours (max: 3)", default="1")
    parser.add_argument("-R", "--retry", help="Retry on failed login (default: False)", default=False, action='store_true')

    args = parser.parse_args()

    section=args.profile
    account=args.account
    fetch_profiles = args.profiles

    global tokenDuration
    tokenDuration = int(args.duration) * 60 * 60

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

    print("Warning: This script will overwrite your AWS credentials stored at "+credentials_path+", section ["+section+"]\n")
    loginSuccessful = None
    while loginSuccessful is None or (args.retry and loginSuccessful is False):
        if haveOnePassword(args.op_item):
            try:
                _signinToken = check_output(["op", "signin", "--account", args.op_account, "--raw"])
                secret = json.loads(check_output(["op", "item", "get", args.op_item, "--format", "json", "--session", _signinToken.decode('utf-8')]))
                for f in secret['fields']:
                    if f["id"] == "username":
                        username = f["value"]
                    if f["id"] == "password":
                        password = f["value"]
                    if f["type"] == "OTP":
                        otp = f["totp"]
            except CalledProcessError:
                print("Could not login with 1Password")

        if username is None or password is None:
            # Get the federated credentials from the user
            if lastuser != "":
                username = input(r"Privileged user (e.g. adm\dev_aly) [" + lastuser + "]: ")
            else:
                username = input(r"Privileged user (e.g. adm\dev_aly): ")

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

        # 2nd HTTP request: POST the username and password
        response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification, allow_redirects=True)
        #Get the challenge token from the user to pass to LinOTP (challengeQuestionInput)
        if otp is not None:
            token = otp
        else:
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
        # Error handling: If ADFS does not return a SAML assertion response, we should not continue
        if (assertion == ''):
            print('Your login failed, please contact launch control or check token/username/passwd and try again\n')
            loginSuccessful = False
        else:
            loginSuccessful = True

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

        unfilteredRoles = awsroles.copy()
        unfilteredRoles.sort()

        filterParts = []
        # Filter roles based on the specified account
        if account is not None:
            awsroles = list(filter(lambda x: ":" + account + ":" in x, awsroles))
            filterParts.append("account: '" + account + "'")

        # Filter roles based on role name
        if args.role is not None:
            awsroles = list(filter(lambda x: ("role/" + args.role) in x, awsroles))
            filterParts.append("role: '" + args.role + "'")

        # If user has more than one role, ask the user which one they want, otherwise just proceed
        awsroles.sort()
        print("")
        if len(awsroles) == 0:
            print('No role found for ' + ", ".join(filterParts) + '. Available roles:')
            for awsrole in unfilteredRoles:
                print(awsrole.split(',')[0])
            raise Exception('No role found for ' + ", ".join(filterParts))
        elif len(awsroles) > 1:
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

        fetched_profiles = []

        if len(fetch_profiles) > 0:
            profiles = fetch_profiles.split(',')
            for awsrole in awsroles:
                role_arn = awsrole.split(',')[0]
                principal_arn = awsrole.split(',')[1]
                section = awsrole.split(':role/')[1]
                section = re.split(r'\W+', section)[0]

                if section in profiles:
                    fetched_profiles.append(section)
                    token = setProfile(section, role_arn, principal_arn)
                    setConfig(section, profile_region, profile_output)
        else:
            token = setProfile(section, role_arn, principal_arn)
            setConfig(section, profile_region, profile_output)

        if token is None:
            raise Exception('Assuming role failed for unknown reasons')

        os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
        with open(credentials_path, 'w') as configfile:
            credentials_config.write(configfile)

        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w') as configfile:
            config_config.write(configfile)

        # Give the user some basic info as to what has just happened
        print('\n----------------------------------------------------------------')
        
        if len(fetch_profiles) > 0:
            print(f'These valid AWS profiles ({",".join(fetched_profiles)}) was fetched has been stored in the AWS configuration file {credentials_path}')
        else:
            print(f'Your AWS access key pair has been stored in the AWS configuration file {credentials_path}')
        
        print('Note that it will expire in ' + str(datetime.timedelta(seconds=tokenDuration)) + ' hours')
        print('----------------------------------------------------------------\n')

        return username, token['Credentials']['AccessKeyId'], token['Credentials']['SecretAccessKey'], token['Credentials']['SessionToken']


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)

#!/usr/bin/env python
#

from __future__ import annotations

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
from bs4 import BeautifulSoup, Tag
from subprocess import check_output, CalledProcessError
import json
from typing import Optional, Dict, Tuple, Any
#import logging
#logging.basicConfig(level=logging.DEBUG)

def load_env_file() -> None:
    """Load environment variables from .env file if it exists."""
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
    if os.path.exists(env_file):
        with open(env_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Only set if not already in environment (CLI args take precedence)
                    if key not in os.environ:
                        os.environ[key] = value

def get_env_with_fallback(env_var: str, fallback: Any = None) -> Any:
    """Get environment variable with fallback value."""
    value = os.environ.get(env_var)
    if value is None:
        return fallback
    # Convert string values to appropriate types
    if isinstance(fallback, bool):
        return value.lower() in ('true', '1', 'yes', 'on')
    elif isinstance(fallback, int):
        try:
            return int(value)
        except ValueError:
            return fallback
    return value

def haveOnePassword() -> bool:
    try:
        check_output(["op"])
        return True
    except:  # noqa: E722
        return False

def setProfile(
    section: str, 
    role_arn: str, 
    principal_arn: str, 
    client: Any, 
    credentials_config: configparser.RawConfigParser, 
    assertion: str, 
    tokenDuration: int, 
    profile_region: str
) -> Optional[Dict[str, Any]]:
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
        return None

def setConfig(section: str, region: str, output: str, config_config: configparser.RawConfigParser) -> None:
    # Write the AWS config file
    if section != "default":
        config_section = f"profile {section}"
    else:
        config_section = section

    if not config_config.has_section(config_section):
        config_config.add_section(config_section)
    config_config.set(config_section, 'region', region)
    config_config.set(config_section, 'output', output)

# noinspection PyPackageRequirements
def main() -> None:
    try:
        implementation()
    except KeyboardInterrupt:
        print("\n\nExiting...")
        exit(0)

def implementation() -> Tuple[str, str, str, str]:    
    # Load environment variables from .env file
    load_env_file()
    
    # Variables
    username: Optional[str] = None
    password: Optional[str] = None
    otp: Optional[str] = None
    token: Optional[Dict[str, Any]] = None
    role_arn: str = ""
    principal_arn: str = ""
    assertion: str = ""
    profile_output: str = 'json'
    sslverification: bool = True
    idpentryurl: str = 'https://federation.visma.com/adfs/ls/idpinitiatedsignon.aspx?loginToRp=urn:amazon:webservices'
    credentials_path: str = os.path.join(os.path.expanduser("~"), ".aws", "credentials")
    config_path: str = os.path.join(os.path.expanduser("~"), ".aws", "config")
    pumaws_configpath: str = os.path.join(os.path.expanduser("~"), ".pum-aws")

    # Get environment variable defaults
    default_profile = get_env_with_fallback('PUM_PROFILE', 'default')
    default_region = get_env_with_fallback('PUM_REGION', 'eu-central-1')
    default_profiles = get_env_with_fallback('PUM_PROFILES', '')
    default_duration = get_env_with_fallback('PUM_DURATION', '1')
    default_retry = get_env_with_fallback('PUM_RETRY', False)
    default_username = get_env_with_fallback('PUM_USERNAME', None)
    default_role = get_env_with_fallback('PUM_ROLE', None)
    default_account = get_env_with_fallback('PUM_ACCOUNT', None)
    default_no_op = get_env_with_fallback('PUM_NO_OP', False)
    
    # Use environment defaults for 1Password, but keep existing logic as fallback
    default_op_account = get_env_with_fallback('PUM_OP_ACCOUNT', "visma")
    default_op_item_name = get_env_with_fallback('PUM_OP_ITEM', "Federation ADM")

    parser = argparse.ArgumentParser(description="Get temporary AWS credentials using Visma federated access with privileged users.")
    parser.add_argument("--role", help="Role name", default=default_role, metavar="PUM_ROLE")
    parser.add_argument("-p", "--profile", default=default_profile, help=f"Store credentials for a non-default AWS profile (default: {default_profile})", metavar="PUM_PROFILE")
    parser.add_argument("-a", "--account", help="Filter roles for the given AWS account", default=default_account, metavar="PUM_ACCOUNT")
    parser.add_argument("-r", "--region", help=f"Configure profile for the specified AWS region (default: {default_region})", default=default_region, metavar="PUM_REGION")
    parser.add_argument("-m", "--profiles", help="Fetch pre-defined profiles separated with ,", default=default_profiles, metavar="PUM_PROFILES")
    parser.add_argument("-d", "--duration", help="Token duration time in hours (min: 1, max: 3)", default=default_duration, metavar="PUM_DURATION")
    parser.add_argument("-R", "--retry", help="Retry on failed login (default: False)", default=default_retry, action='store_true')
    parser.add_argument("-u", "--username", help="Username to use. 1Pass username takes precedence", default=default_username, metavar="PUM_USERNAME")
    
    parser.add_argument("--op-account", help=f"Name of the 1Password account (default: '{default_op_account}')", default=default_op_account, dest="op_account", metavar="PUM_OP_ACCOUNT")
    parser.add_argument("--op-item", help=f"Name of the 1Password item (default: '{default_op_item_name}')", default=default_op_item_name, dest="op_item", metavar="PUM_OP_ITEM")
    parser.add_argument("-o", "--no-op", help="Disable 1Pass CLI integration (default: False)", default=default_no_op, action='store_true')

    args = parser.parse_args()

    section=args.profile
    account=args.account
    fetch_profiles = args.profiles
    username = args.username

    # Convert hours to seconds, clamping between 1 and 3 hours
    SECONDS_PER_HOUR = 3600
    duration_hours = max(1, min(3, int(args.duration)))  # Clamp between 1 and 3
    if duration_hours != int(args.duration):
        print(f"Warning: Duration clamped from {args.duration} to {duration_hours} hours (valid range: 1-3)")
    tokenDuration = duration_hours * SECONDS_PER_HOUR

    profile_region = args.region
        
    # Read last used user name
    pumaws_config = configparser.RawConfigParser()
    pumaws_config.read(pumaws_configpath)
    lastuser: str = ""
    use_aliases: str = "false"
    if pumaws_config.has_section("default"):
        lastuser = pumaws_config.get("default", "username")
        if pumaws_config.has_option("default", "use_account_aliases"):
            use_aliases = pumaws_config.get("default", "use_account_aliases")

    loginSuccessful: Optional[bool] = None
    firstTry: bool = True
    passwordPreset: bool = False
    usernamePreset: bool = False
    print(f"Warning: This script will overwrite your AWS credentials stored at {credentials_path}, section [{section}]\n")
    while loginSuccessful is None or (args.retry and loginSuccessful is False):
        if not args.no_op and haveOnePassword():
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

        if username is None or (firstTry is False and usernamePreset is False):
            # Get the federated credentials from the user
            if lastuser != "":
                username = input(rf"Privileged user (e.g. adm\dev_aly) [{lastuser}]: ")
            else:
                username = input(r"Privileged user (e.g. adm\dev_aly): ")

            if username == "":
                username = lastuser
        else:
            if firstTry:
                usernamePreset = True
            print(f"Using username: {username}")

        if password is None or (firstTry is False and passwordPreset is False):
            password = getpass.getpass(prompt='Domain password: ')
        else:
            if firstTry:
                passwordPreset = True
            print("Password already set.")

        # Save last used user name
        if lastuser != username and username is not None and username != "":
            if not pumaws_config.has_section("default"):
                pumaws_config.add_section("default")
            pumaws_config.set("default", 'username', username)
            with open(pumaws_configpath, 'w') as configfile:
                pumaws_config.write(configfile)

        # 1st HTTP request: GET the login form
        session: requests.Session = requests.Session()
        # Parse the response and extract all the necessary values
        formresponse = session.get(idpentryurl, verify=sslverification, allow_redirects=True)
        idpauthformsubmiturl = formresponse.url
        formsoup = BeautifulSoup(formresponse.text, 'html.parser') #.decode('utf8')
        payload: Dict[str, str] = {}
        for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
            if isinstance(inputtag, Tag):
                name = inputtag.get('name', '')
                value = inputtag.get('value', '')
                if isinstance(name, str) and isinstance(value, str):
                    if "username" in name.lower():
                        payload[name] = username or ""
                    elif "authmethod" in name.lower():
                        payload[name] = "FormsAuthentication"
                    elif "password" in name.lower():
                        payload[name] = password or ""
                    else:
                        #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                        payload[name] = value

        # 2nd HTTP request: POST the username and password
        response = session.post(idpauthformsubmiturl, data=payload, verify=sslverification, allow_redirects=True)
        
        #Get the challenge token from the user to pass to LinOTP (challengeQuestionInput)
        if not firstTry:
            otp = None

        mfa_token: str
        if otp is not None:
            mfa_token = otp
        else:
            print("Visma Google Auth 2FA Token:", end=" ")
            mfa_token = input()
        
        # Build nested data structure, parse the response and extract all the necessary values
        tokensoup = BeautifulSoup(response.text, 'html.parser') #.decode('utf8')
        payload = {}
        for inputtag in tokensoup.find_all(re.compile('(INPUT|input)')):
            if isinstance(inputtag, Tag):
                name = inputtag.get('name','')
                value = inputtag.get('value','')
                if isinstance(name, str) and isinstance(value, str):
                    if "challenge" in name.lower():
                        payload[name] = mfa_token
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
        assertion: str = ''
        # Look for the SAMLResponse attribute of the input tag (determined by analyzing the debug print lines above)
        for inputtag in soup.find_all('input'):
            if isinstance(inputtag, Tag):
                if inputtag.get('name') == 'SAMLResponse':
                    value = inputtag.get('value')
                    if isinstance(value, str):
                        assertion = value
        # Error handling: If ADFS does not return a SAML assertion response, we should not continue
        firstTry = False
        if not assertion:
            print('Your login failed, please contact launch control or check token/username/passwd and try again\n')
            loginSuccessful = False
        else:
            loginSuccessful = True

    # Parse the returned assertion and extract the authorized roles
    awsroles: list[str] = []
    root = ET.fromstring(base64.b64decode(assertion))
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role':
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                if saml2attributevalue.text:
                    awsroles.append(saml2attributevalue.text)
    # Note the format of the attribute value should be role_arn,principal_arn
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = f"{chunks[1]},{chunks[0]}"
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    unfilteredRoles: list[str] = awsroles.copy()
    unfilteredRoles.sort()

    filterParts: list[str] = []
    # Filter roles based on the specified account
    if account is not None:
        awsroles = list(filter(lambda x: account in x, awsroles))
        filterParts.append(f"account: '{account}'")

    # Filter roles based on role name
    if args.role is not None:
        awsroles = list(filter(lambda x: (f"role/{args.role}") in x, awsroles))
        filterParts.append(f"role: '{args.role}'")

    # Check if no roles found after filtering
    if len(awsroles) == 0:
        print(f'No role found for {", ".join(filterParts)}. Available roles:')
        for awsrole in unfilteredRoles:
            print(awsrole.split(',')[0])
        raise Exception(f'No role found for {", ".join(filterParts)}')

    # If user has more than one role, ask the user which one they want, otherwise just proceed
    awsroles.sort()
    print("")
    if len(awsroles) > 1:
        # Only show interactive selection if NOT in multi-profile mode
        if len(fetch_profiles) == 0:
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
            # Multi-profile mode with multiple roles - use first one
            role_arn = awsroles[0].split(',')[0]
            principal_arn = awsroles[0].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    # Ensure role_arn and principal_arn are properly set
    assert role_arn and principal_arn, "Role ARN and Principal ARN must be set"

    # Write the AWS STS token into the AWS credential file
    credentials_config = configparser.RawConfigParser()
    credentials_config.read(credentials_path)

    config_config = configparser.RawConfigParser()
    config_config.read(config_path)

    client = boto3.client('sts')

    fetched_profiles: list[str] = []

    if len(fetch_profiles) > 0:
        # Multi-profile mode: fetch multiple profiles by name
        profiles: list[str] = fetch_profiles.split(',')
        last_token: Optional[Dict[str, Any]] = None
        for awsrole in awsroles:
            current_role_arn = awsrole.split(',')[0]
            current_principal_arn = awsrole.split(',')[1]
            section = awsrole.split(':role/')[1]
            section = re.split(r'\W+', section)[0]

            if section in profiles:
                fetched_profiles.append(section)
                last_token = setProfile(section, current_role_arn, current_principal_arn, client, credentials_config, assertion, tokenDuration, profile_region)
                setConfig(section, profile_region, profile_output, config_config)
        
        token = last_token  # Use the last token for validation
    else:
        # Single-role mode: use the selected role
        token = setProfile(section, role_arn, principal_arn, client, credentials_config, assertion, tokenDuration, profile_region)
        setConfig(section, profile_region, profile_output, config_config)

    if token is None:
        raise Exception('Assuming role failed for unknown reasons')
    
    assert username, 'Username cannot be None at this point'

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
    
    print(f'Note that it will expire in {datetime.timedelta(seconds=tokenDuration)} hours')
    print('----------------------------------------------------------------\n')

    return username, token['Credentials']['AccessKeyId'], token['Credentials']['SecretAccessKey'], token['Credentials']['SessionToken']


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(e)

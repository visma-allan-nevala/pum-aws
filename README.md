# Purpose
The purpose of this script is to allow Visma employees to work with the [AWS CLI](https://aws.amazon.com/cli/) using federated access with privileged users ([Privileged User Management](https://confluence.visma.com/display/VCDM/PUM+-+Privileged+User+Management)). Federated access with privileged users - not AWS IAM users - must be used for all personal access to AWS.

# How does it work?
1) The script asks the user for privileged user credentials and a valid 2FA token (if you don't have a privileged user, request one in [MIM](https://mimportal.visma.com/identitymanagement/default.aspx))
2) The credentials are submitted to Visma's AFDS identity provider ([federation.visma.com](https://federation.visma.com/adfs/ls/idpinitiatedsignon.aspx))
3) If the authentication is successful, a signed SAML assertion will be returned, containing claims to certain AWS IAM roles for certain AWS accounts (this is based on security group memberships in Active Directory which can be managed in [MIM](https://mimportal.visma.com/identitymanagement/default.aspx))
4) If the SAML assertion contains claims for more than one AWS IAM role, the user is prompted to choose one of them
5) The SAML assertion is sent to AWS and verified by AWS (Visma's ADFS must be trusted in the AWS account you are trying to log into, this is usually done by VITC when they create the AWS account)
6) If the SAML assertion is verified successfully, AWS returns temporary security credentials for the chosen role. These credentials can be used for running AWS CLI and are valid for 1 hour.

# Prerequisites
* [Python 3](https://www.python.org/downloads/)
* Install dependencies: `pip install -r requirements.txt`

# Usage
	
	git clone https://stash.visma.com/scm/vcm/pum-aws.git
	cd pum-aws
	
	python pum-aws.py
	<provide privileged user credentials and 2fa token>
	aws --profile vadfs s3api list-buckets
	
## Example

```
C:\Users\alexander.lystad\pum-aws>python pum-aws.py
Warning: This script will overwrite your default AWS credentials stored at C:\Users\alexander.lystad\.aws\credentials

Privileged user (e.g. adm\dev_aly): adm\dev_aly
Domain password:
Visma Google Auth 2FA Token: 444692

Please choose the AWS account and role you would like to assume:
[ 0 ]:  arn:aws:iam::095344953043:role/RDSAlice
[ 1 ]:  arn:aws:iam::039882259752:role/ViewOnlyAccess
[ 2 ]:  arn:aws:iam::585848786654:role/AdministratorAccess
[ 3 ]:  arn:aws:iam::095344953043:role/PowerUserAccess
Selection: 3

----------------------------------------------------------------
Your AWS access key pair has been stored in the AWS configuration file C:\Users\alexander.lystad\.aws\credentials
Note that it will expire at 2018-05-22 14:46:28+00:00
Usage example: aws s3api list-buckets
----------------------------------------------------------------


C:\Users\alexander.lystad\pum-aws>aws s3api list-buckets
{
    "Owner": {
        "DisplayName": "vlpaws+095344953043",
        "ID": "18620d35a724458d7d9444b6e01ac81e2eb49e3237789e91f85465b445b46f42"
    },
    "Buckets": [
        {
            "CreationDate": "2017-10-25T11:13:28.000Z",
            "Name": "elasticbeanstalk-eu-west-1-095344953043"
        },
        {
            "CreationDate": "2018-04-25T14:11:10.000Z",
            "Name": "getublockorigin.com"
        },
        {
            "CreationDate": "2018-04-25T23:12:41.000Z",
            "Name": "getublockorigin.com-cloudfront-logs"
        }
    ]
}
```
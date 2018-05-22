# Purpose
The purpose of this tool is to allow federated users (Privileged User Management) to work with the AWS CLI.

# Prerequisites
* Python 3

# Usage

	python pum-aws.py
	<provide privileged user username, password and 2fa token>
	aws --profile vadfs s3api list-buckets
	
Example:

```
C:\Users\alexander.lystad\Downloads\aws-visma-federated-api-access>python pum-aws.py
Username: adm\dev_aly
Domain Password:
Visma Google Auth 2FA Token: 444692

Please choose the AWS account and role you would like to assume:
[ 0 ]:  arn:aws:iam::095344953043:role/RDSAlice
[ 1 ]:  arn:aws:iam::039882259752:role/ViewOnlyAccess
[ 2 ]:  arn:aws:iam::708152831771:role/ViewOnlyAccess
[ 3 ]:  arn:aws:iam::383381053630:role/BillingInfo
[ 4 ]:  arn:aws:iam::585848786654:role/AdministratorAccess
[ 5 ]:  arn:aws:iam::095344953043:role/PowerUserAccess
[ 6 ]:  arn:aws:iam::095344953043:role/AdministratorAccess
[ 7 ]:  arn:aws:iam::252650166657:role/AdministratorAccess
[ 8 ]:  arn:aws:iam::100074597024:role/ReadOnlyAccess
[ 9 ]:  arn:aws:iam::039882259752:role/AdministratorAccess
[ 10 ]:  arn:aws:iam::485937710382:role/AdministratorAccess
[ 11 ]:  arn:aws:iam::312327183351:role/AdministratorAccess
[ 12 ]:  arn:aws:iam::754435796660:role/AdministratorAccess
[ 13 ]:  arn:aws:iam::901509397090:role/AdministratorAccess
[ 14 ]:  arn:aws:iam::708152831771:role/AdministratorAccess
[ 15 ]:  arn:aws:iam::221836728622:role/AdministratorAccess
[ 16 ]:  arn:aws:iam::359902235356:role/AdministratorAccess
[ 17 ]:  arn:aws:iam::926538462187:role/AdministratorAccess
[ 18 ]:  arn:aws:iam::734735494626:role/AdministratorAccess
[ 19 ]:  arn:aws:iam::833432581518:role/PowerUserAccess
[ 20 ]:  arn:aws:iam::833432581518:role/AdministratorAccess
[ 21 ]:  arn:aws:iam::229394205472:role/AdministratorAccess
[ 22 ]:  arn:aws:iam::042467748676:role/AdministratorAccess
Selection:  6

----------------------------------------------------------------
Your AWS access key pair has been stored in the AWS configuration file C:\Users\alexander.lystad\.aws\credentials
Note that it will expire at 2018-05-22 14:46:28+00:00
Usage example: aws --profile vadfs s3api list-buckets
----------------------------------------------------------------


C:\Users\alexander.lystad\Downloads\aws-visma-federated-api-access>aws --profile vadfs s3api list-buckets
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
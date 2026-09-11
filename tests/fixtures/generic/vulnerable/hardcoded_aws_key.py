# Fixture vulnérable : clé AWS Access Key hardcodée
import boto3

AWS_ACCESS_KEY = "AKIA1234567890ABCDEF"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

client = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY)

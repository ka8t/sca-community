# Fixture clean : clé AWS via variable d'environnement
import os
import boto3

AWS_ACCESS_KEY = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

client = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY)

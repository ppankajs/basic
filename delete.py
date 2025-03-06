import boto3
import os
from dotenv import load_dotenv

# ✅ Load environment variables from .env file
load_dotenv()

# ✅ Initialize AWS DynamoDB Client
dynamodb = boto3.client(
    "dynamodb",
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN")  # Only if using temporary credentials
)

def delete_dynamodb_table(table_name):
    """Deletes a DynamoDB table"""
    try:
        response = dynamodb.delete_table(TableName=table_name)
        print(f"✅ Table '{table_name}' deletion started. Status: {response['TableDescription']['TableStatus']}")
    except dynamodb.exceptions.ResourceNotFoundException:
        print(f"❌ Table '{table_name}' does not exist.")
    except Exception as e:
        print(f"❌ Error deleting table: {e}")

# ✅ Call the function with your table name
delete_dynamodb_table("userspressi")

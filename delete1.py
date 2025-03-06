import boto3
import os
from dotenv import load_dotenv

load_dotenv()

dynamodb = boto3.resource(
    "dynamodb",
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN")
)

table_name = "userspressi"
table = dynamodb.Table(table_name)

def delete_all_items():
    """Deletes all items in the table without deleting the table itself."""
    try:
        scan = table.scan()
        for item in scan.get("Items", []):
            table.delete_item(Key={"email": item["email"]})  # Use primary key for deletion
            print(f"🗑️ Deleted item: {item}")

        print(f"✅ All items deleted from '{table_name}'.")
    except Exception as e:
        print(f"❌ Error deleting items: {e}")

delete_all_items()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import boto3
import botocore
import json
import re
import os
import time
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
from werkzeug.utils import secure_filename

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Initialize DynamoDB resource
dynamodb = boto3.resource(
    'dynamodb',
    region_name=os.getenv("AWS_REGION"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    aws_session_token=os.getenv("AWS_SESSION_TOKEN")  # Optional
)

TABLE_NAME = "userspressi"

# Function to create the DynamoDB table if it doesn't exist
def create_users_table():
    try:
        existing_tables = list(dynamodb.tables.all())

        if TABLE_NAME not in [table.name for table in existing_tables]:
            print(f"Creating table '{TABLE_NAME}'...")
            table = dynamodb.create_table(
                TableName=TABLE_NAME,
                KeySchema=[{"AttributeName": "email", "KeyType": "HASH"}],  # Primary key
                AttributeDefinitions=[{"AttributeName": "email", "AttributeType": "S"}],
                ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
            )

            # Wait for the table to be created
            table.wait_until_exists()
            print(f"Table '{TABLE_NAME}' created successfully!")
        else:
            print(f"Table '{TABLE_NAME}' already exists.")
    
    except (NoCredentialsError, PartialCredentialsError):
        print("AWS Credentials not found! Make sure they are set in the .env file.")
        exit(1)

# Call function to ensure table exists
create_users_table()

# Connect to existing DynamoDB table
users_table = dynamodb.Table(TABLE_NAME)


@app.route('/')
def index():
    return redirect(url_for('home'))


# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     if request.method == 'POST':
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']

#         # ✅ **Strict Name Validation (Only Alphabets)**
#         if not re.match(r'^[A-Za-z ]+$', name):  # Allows only letters and spaces
#             flash('Name must contain only alphabets.', 'danger')
#             return redirect(url_for('register'))
        
#         # ✅ **Strict Email Validation**
#         email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
#         if not re.match(email_regex, email):
#             flash('Invalid email address format. Please enter a valid email.', 'danger')
#             return redirect(url_for('register'))

#         # ✅ **Password Complexity Validation**
#         password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
#         if not re.match(password_regex, password):
#             flash('Password must contain at least one uppercase letter, one number, one special character, and be at least 6 characters long.', 'danger')
#             return redirect(url_for('register'))

#         # Hash the password for security
#         hashed_password = generate_password_hash(password)

#         # ✅ **Check if Email Already Exists**
#         response = users_table.get_item(Key={'email': email})
#         if 'Item' in response:
#             flash('Email already registered. Please log in.', 'warning')
#             return redirect(url_for('login'))

#         # ✅ **Save User Details in DynamoDB**
#         users_table.put_item(
#             Item={
#                 'email': email,  # Primary Key
#                 'name': name,
#                 'password': hashed_password  # Store hashed password
#             }
#         )

#         flash('Registration successful! Please login.', 'success')
#         return redirect(url_for('login'))
    
#     return render_template('register.html')


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         email = request.form.get('email')
#         password = request.form.get('password')

#         # Fetch user details from DynamoDB
#         response = users_table.get_item(Key={'email': email})
#         user = response.get('Item')

#         if not user:
#             flash('Invalid user details. Please check your email and try again.', 'danger')
#             return redirect(url_for('login'))

#         # Verify password
#         if check_password_hash(user['password'], password):
#             session['user_id'] = email
#             session['user_name'] = user['name']
#             flash('Login successful!', 'success')
#             return redirect(url_for('home'))
#         else:
#             flash('Incorrect password. Please try again.', 'danger')

#     return render_template('login.html')


# ✅ AWS Configuration
AWS_REGION = "us-east-1"

# ✅ Initialize AWS Clients
sqs_client = boto3.client("sqs", region_name=AWS_REGION)
sns_client = boto3.client("sns", region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
users_table = dynamodb.Table("userspressi")  # Ensure table exists

# ✅ Get or Create SQS Queue
def get_or_create_sqs_queue(queue_name):
    """ Get existing SQS Queue URL or create a new one """
    try:
        queue = sqs_client.get_queue_url(QueueName=queue_name)
        print(f"✅ SQS Queue '{queue_name}' already exists: {queue['QueueUrl']}")
        return queue["QueueUrl"]
    except sqs_client.exceptions.QueueDoesNotExist:
        response = sqs_client.create_queue(
            QueueName=queue_name,
            Attributes={"DelaySeconds": "5", "VisibilityTimeout": "30"}
        )
        print(f"🆕 SQS Queue '{queue_name}' was created: {response['QueueUrl']}")
        return response["QueueUrl"]

# ✅ Get or Create SNS Topic
def get_or_create_sns_topic(topic_name):
    """ Get existing SNS Topic ARN or create a new one """
    topics = sns_client.list_topics()["Topics"]
    for topic in topics:
        if topic_name in topic["TopicArn"]:
            print(f"✅ SNS Topic '{topic_name}' already exists: {topic['TopicArn']}")
            return topic["TopicArn"]
    
    response = sns_client.create_topic(Name=topic_name)
    print(f"🆕 SNS Topic '{topic_name}' was created: {response['TopicArn']}")
    return response["TopicArn"]

# ✅ Fetch or Create AWS Resources
SQS_QUEUE_URL = get_or_create_sqs_queue("buddyloans-queue")
SNS_TOPIC_ARN = get_or_create_sns_topic("buddyloans-topic")

# ✅ Subscribe Email to SNS (Auto-Confirm)
def subscribe_email(email):
    """Automatically subscribe and confirm the email without manual action"""
    try:
        response = sns_client.subscribe(
            TopicArn=SNS_TOPIC_ARN,
            Protocol="email",
            Endpoint=email,
            ReturnSubscriptionArn=True  # Get ARN immediately
        )
        subscription_arn = response["SubscriptionArn"]

        if subscription_arn:  # If ARN is returned, it means the subscription is active
            print(f"✅ Email {email} auto-subscribed with ARN: {subscription_arn}")

            # ✅ Update DynamoDB - Mark subscription as confirmed
            users_table.update_item(
                Key={'email': email},
                UpdateExpression="SET subscription_status = :s",
                ExpressionAttributeValues={":s": "confirmed"}
            )

            return True  # ✅ Auto-confirmed
        else:
            print(f"⚠️ Subscription pending for {email}. Check SNS settings.")
            return False  # ❌ Pending confirmation

    except Exception as e:
        print(f"❌ Error subscribing {email}: {e}")
        return False

# ✅ Send Welcome Email (Now Triggered at Login)
def send_email_notification(email, name):
    """Send welcome email via SNS only if the user is already subscribed"""
    try:
        # ✅ Step 1: Check if the user is already subscribed
        subscriptions = sns_client.list_subscriptions_by_topic(TopicArn=SNS_TOPIC_ARN)['Subscriptions']
        user_subscription = next((sub for sub in subscriptions if sub['Endpoint'] == email), None)

        if user_subscription and user_subscription['SubscriptionArn'] != 'PendingConfirmation':
            # ✅ Step 2: User is already subscribed, send the email
            message = f"Hello {name},\n\nThank you for registering on BuddyLoans. We’re excited to have you!\n\nBest Regards,\nBuddyLoans Team"

            response = sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,  # Publish to the topic instead of TargetArn
                # TargetArn=user_subscription['Endpoint'],
                Subject="Welcome to BuddyLoans!",
                Message=message,
                MessageAttributes={
                    'email': {
                        'DataType': 'String',
                        'StringValue': email  # Ensures SNS filters only for this email
                    }
                }
            )
            print(f"📨 Email Sent to {email} - MessageID: {response['MessageId']}")
        else:
            print(f"⚠️ Email not sent because {email} is still pending confirmation.")

    except Exception as e:
        print(f"❌ Error sending email: {e}")

        
# ✅ Register Route (No Email Sent Here)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # ✅ **Validation Checks**
        if not re.match(r'^[A-Za-z ]+$', name):
            flash('Name must contain only alphabets.', 'danger')
            return redirect(url_for('register'))

        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            flash('Invalid email format.', 'danger')
            return redirect(url_for('register'))

        password_regex = r'^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
        if not re.match(password_regex, password):
            flash('Password must have at least one uppercase, one number, one special character, and be at least 6 characters long.', 'danger')
            return redirect(url_for('register'))

        # ✅ **Check if Email Exists in DynamoDB**
        try:
            response = users_table.get_item(Key={'email': email})
            if 'Item' in response:
                flash('Email already registered. Please log in.', 'warning')
                return redirect(url_for('login'))
        except Exception as e:
            print(f"❌ Error Checking DynamoDB: {e}")
            flash("Internal Server Error. Please try again later.", 'danger')
            return redirect(url_for('register'))

        # ✅ **Save User in DynamoDB**
        hashed_password = generate_password_hash(password)
        users_table.put_item(
            Item={
                'email': email,
                'name': name,
                'password': hashed_password,
                'subscription_status': 'pending'  # Mark as pending until confirmed
            }
        )

        # ✅ **Subscribe Email Automatically**
        subscribe_email(email)

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# ✅ Login Route (Triggers Email)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user details from DynamoDB
        response = users_table.get_item(Key={'email': email})
        user = response.get('Item')

        if not user:
            flash('Invalid user details. Please check your email and try again.', 'danger')
            return redirect(url_for('login'))

        # Verify password
        if check_password_hash(user['password'], password):
            session['user_id'] = email
            session['user_name'] = user['name']

            # ✅ Check subscription and send email if needed
            send_email_notification(email, user['name'])

            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Incorrect password. Please try again.', 'danger')

    return render_template('login.html')


@app.route('/home')
def home():
    if 'user_id' in session:
        return render_template('home.html', name=session['user_name'])
    return render_template('home.html', name="Guest")


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ✅ AWS Configuration
AWS_REGION = "us-east-1"
S3_BUCKET_NAME = "buddyloans-profile-pics"  # Change to your desired bucket name

# ✅ Initialize AWS Clients
s3_client = boto3.client("s3", region_name=AWS_REGION)
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
users_table = dynamodb.Table("userspressi")  # Your DynamoDB table


# ✅ Function to Create/Get S3 Bucket
def get_or_create_s3_bucket():
    """Ensures that the S3 bucket exists before uploading."""
    try:
        # Check if the bucket exists
        existing_buckets = [bucket["Name"] for bucket in s3_client.list_buckets()["Buckets"]]

        if S3_BUCKET_NAME not in existing_buckets:
            print(f"⚡ Creating S3 bucket: {S3_BUCKET_NAME} in {AWS_REGION}")

            # Ensure correct region while creating the bucket
            if AWS_REGION == "us-east-1":
                s3_client.create_bucket(Bucket=S3_BUCKET_NAME)
            else:
                s3_client.create_bucket(
                    Bucket=S3_BUCKET_NAME,
                    CreateBucketConfiguration={"LocationConstraint": AWS_REGION}
                )

            # Wait for AWS to propagate the bucket creation
            time.sleep(5)

            # Make the bucket public (optional)
            s3_client.put_bucket_acl(Bucket=S3_BUCKET_NAME, ACL="public-read")
            print(f"✅ S3 Bucket Created: {S3_BUCKET_NAME}")

        else:
            print(f"⚡ S3 Bucket {S3_BUCKET_NAME} already exists.")

    except botocore.exceptions.ClientError as e:
        print(f"❌ Error creating S3 bucket: {e}")
        

# ✅ Function to Upload File to S3
def upload_file_to_s3(file, folder="profile_pics/"):
    """Uploads a file to S3 only if the bucket exists."""
    try:
        # Ensure bucket exists before uploading
        get_or_create_s3_bucket()

        # Re-check if bucket exists
        existing_buckets = [bucket["Name"] for bucket in s3_client.list_buckets()["Buckets"]]
        if S3_BUCKET_NAME not in existing_buckets:
            print(f"❌ Bucket {S3_BUCKET_NAME} does not exist. Retrying in 5 seconds...")
            time.sleep(5)
            return None

        filename = secure_filename(file.filename)
        s3_path = os.path.join(folder, filename)

        # Upload file to S3
        s3_client.upload_fileobj(
            file, S3_BUCKET_NAME, s3_path,
            # ExtraArgs={"ACL": "public-read"}
        )

        file_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_path}"
        print(f"✅ Uploaded to S3: {file_url}")
        return file_url

    except Exception as e:
        print(f"❌ Error uploading to S3: {e}")
        return None

# ✅ Profile Page Route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    email = session['user_id']
    response = users_table.get_item(Key={'email': email})
    user = response.get('Item')

    return render_template('profile.html', user=user)

# ✅ Upload Profile Picture Route
@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'user_id' not in session:
        flash('Please log in first.', 'warning')
        return redirect(url_for('login'))

    email = session['user_id']
    file = request.files.get('profile_pic')

    if not file:
        flash("No file selected!", "danger")
        return redirect(url_for('profile'))

    # ✅ Upload file to S3
    profile_pic_url = upload_file_to_s3(file)

    if profile_pic_url:
        # ✅ Update DynamoDB with new profile picture URL
        users_table.update_item(
            Key={'email': email},
            UpdateExpression="SET profile_pic_url = :url",
            ExpressionAttributeValues={":url": profile_pic_url}
        )

        flash("Profile picture updated successfully!", "success")
    else:
        flash("File upload failed. Try again.", "danger")

    return redirect(url_for('profile'))


if __name__ == '__main__':
    app.run(debug=True)

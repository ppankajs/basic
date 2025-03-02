from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import boto3
import re
import os
import time
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

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

TABLE_NAME = "usersprasanna"

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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Validate email format
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            flash('Invalid email address', 'danger')
            return redirect(url_for('register'))

        # Validate password length
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'danger')
            return redirect(url_for('register'))
        
        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Check if email already exists
        response = users_table.get_item(Key={'email': email})
        if 'Item' in response:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))

        # Save user details in DynamoDB
        users_table.put_item(
            Item={
                'email': email,  # Primary Key
                'name': name,
                'password': hashed_password  # Store hashed password
            }
        )

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Fetch user details from DynamoDB
        response = users_table.get_item(Key={'email': email})
        user = response.get('Item')

        if user and check_password_hash(user['password'], password):
            session['user_id'] = email
            session['user_name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password', 'danger')

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


if __name__ == '__main__':
    app.run(debug=True)

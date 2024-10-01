import requests
import socket
import jwt
from datetime import datetime, timezone, timedelta
import pytz
import csv

# Function to read email and password from CSV file
def read_credentials(csv_file):
    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip the header row
        for row in reader:
            email, password = row
            return email, password

# Function to get the local IP address
def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

# Function to log in using POST method
def login(session, login_url, email, password):
    payload = {
        'email': email,
        'password': password,
        'deviceType': 'PERSONAL_COMPUTER',
        'ipAddress': get_local_ip(),
        # 'operatingSystem': 'Windows'
    }
    print(f"Payload: {payload}")  # Print the payload for debugging
    response = session.post(login_url, json=payload)
    return response

# Function to refresh the access token using the refresh token
def refresh_access_token(session, refresh_url, refresh_token, user_id):
    payload = {
        'refreshToken': refresh_token,
        'userId': user_id
    }
    response = session.post(refresh_url, json=payload)
    return response

# Function to check if the access token is expired and print how long it has been expired
def is_token_expired(token):
    try:
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        exp_timestamp = decoded_token.get('exp')
        if exp_timestamp:
            exp_datetime = datetime.fromtimestamp(exp_timestamp, timezone.utc)
            current_datetime = datetime.now(timezone.utc)
            if current_datetime >= exp_datetime:
                expired_duration = current_datetime - exp_datetime
                print(f"Token expired {expired_duration} ago")
                return True
            return False
        return True
    except jwt.DecodeError:
        return True

# Main function
def main():
    csv_file = 'credentials.csv'
    login_url = 'https://mapi.maicatech.com/auth/v2/login'  # Replace with the actual login URL
    refresh_url = 'https://mapi.maicatech.com/auth/refresh-token'  # Replace with the actual refresh token URL

    # Read credentials from CSV
    email, password = read_credentials(csv_file)

    # Create a session
    session = requests.Session()

    # Log in to the website
    try:
        response = login(session, login_url, email, password)
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")  # Print the response content for debugging
        if response.status_code == 200:
            print("Login successful")
            try:
                tokens = response.json()
                print(f"Tokens: {tokens}")  # Print the tokens for debugging
                access_token = tokens.get('accessToken')
                refresh_token = tokens.get('refreshToken')
                user_id = tokens.get('userId')

                # Print the access token and refresh token
                print(f"Access Token: {access_token}")
                print(f"Refresh Token: {refresh_token}")

                # Decode the access token to get the expiry timestamp
                decoded_token = jwt.decode(access_token, options={"verify_signature": False})
                exp_timestamp = decoded_token.get('exp')
                if exp_timestamp:
                    exp_datetime = datetime.fromtimestamp(exp_timestamp, timezone.utc)
                    hanoi_tz = pytz.timezone('Asia/Ho_Chi_Minh')
                    exp_datetime_hanoi = exp_datetime.astimezone(hanoi_tz)
                    print(f"Access Token Expiry (UTC): {exp_datetime}")
                    print(f"Access Token Expiry (Hanoi): {exp_datetime_hanoi}")

                    # Calculate the remaining time until the token expires
                    current_datetime_hanoi = datetime.now(hanoi_tz)
                    remaining_time = exp_datetime_hanoi - current_datetime_hanoi
                    remaining_hours = remaining_time.total_seconds() / 3600
                    print(f"Token is valid for {remaining_hours:.2f} hours")

                # Check if the access token is expired
                if is_token_expired(access_token):
                    print("Access token is expired, refreshing...")
                    refresh_response = refresh_access_token(session, refresh_url, refresh_token, user_id)
                    print(f"Refresh Status Code: {refresh_response.status_code}")
                    print(f"Refresh Response Content: {refresh_response.text}")
                    if refresh_response.status_code == 200:
                        new_tokens = refresh_response.json()
                        new_access_token = new_tokens.get('accessToken')
                        new_refresh_token = new_tokens.get('refreshToken')
                        print("Access token refreshed successfully")
                    else:
                        print("Failed to refresh access token")
                else:
                    print("Access token is valid")
            except ValueError as e:
                print(f"Failed to parse JSON response: {e}")
        else:
            print("Login failed")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
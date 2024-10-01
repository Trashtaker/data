from fastapi import FastAPI, HTTPException
import requests
import socket
import jwt
from datetime import datetime, timezone
import pytz
import csv
from datetime import datetime, timedelta

# pip install fastapi
# pip install requests
# pip install pyjwt
# pip install pytz
# uvicorn app:app --reload 
app = FastAPI()

def read_credentials(csv_file):
    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        next(reader)  
        for row in reader:
            email, password = row
            return email, password

def get_local_ip():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    return local_ip

def login(session, login_url, email, password):
    payload = {
        'email': email,
        'password': password,
        'deviceType': 'PERSONAL_COMPUTER',
        'ipAddress': get_local_ip(),
        'operatingSystem': 'Windows'
    }
    response = session.post(login_url, json=payload)
    return response

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

# Function to make a GET request and print the JSON response
def get_json_data(session, url, access_token, params=None):
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    response = session.get(url, headers=headers, params=params)
    if response.status_code == 200:
        try:
            json_data = response.json()
            return json_data
        except ValueError as e:
            print(f"Failed to parse JSON response: {e}")
    else:
        print(f"Failed to get data from {url}")
    return None

# Function to make a POST request and print the JSON response
def post_json_data(session, url, access_token, payload):
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }
    response = session.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        try:
            json_data = response.json()
            return json_data
        except ValueError as e:
            print(f"Failed to parse JSON response: {e}")
    else:
        print(f"Failed to post data to {url}")
    return None

def flatten_and_filter_data(json_data):
    flattened_data = []

    # Check if 'flowmetersData' key exists in json_data
    if 'flowmetersData' not in json_data:
        print("No 'flowmetersData' key found in json_data")
        return flattened_data

    for entry in json_data['flowmetersData']:
        main_consumption = entry.get('consumption')
        date = entry.get('date')
        licence = entry.get('licence')
        locationId = entry.get('locationId')
        brandingId = entry.get('brandingId')
        locationName = entry.get('locationName')
        locationRef = entry.get('locationRef')
        locationCity = entry.get('locationCity')

        # Check if 'lines' key exists in entry
        if 'lines' not in entry:
            print("No 'lines' key found in entry")
            continue

        for line in entry['lines']:

            # Check if 'consumption' key exists in line
            if 'consumption' not in line:
                print(f"No 'consumption' key found in line: {line}")
                continue

            if line['consumption'] != 0:  
                flattened_data.append({
                    'licence': licence,
                    'locationId': locationId,
                    'brandingId': brandingId,
                    'locationName': locationName,
                    'locationRef': locationRef,
                    'locationCity': locationCity,
                    'mainConsumption': main_consumption,
                    'date': date,
                    'lineId': line.get('lineId'),
                    'lineName': line.get('lineName'),
                    'lineConsumption': line.get('consumption'),
                })

    return flattened_data

@app.get("/regions")
def get_regions():
    csv_file = 'credentials.csv'
    login_url = 'https://mapi.maicatech.com/auth/v2/login'
    refresh_url = 'https://mapi.maicatech.com/auth/refresh-token'
    regions_url = 'https://mapi.maicatech.com/group/regions'
    brands_url = 'https://mapi.maicatech.com/device/flowmeter/group/brands'

    # Read credentials from CSV
    email, password = read_credentials(csv_file)

    # Create a session
    session = requests.Session()

    # Log in to the website
    response = login(session, login_url, email, password)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Login failed")

    tokens = response.json()
    access_token = tokens.get('accessToken')
    refresh_token = tokens.get('refreshToken')
    user_id = tokens.get('userId')

    # Check if the access token is expired
    if is_token_expired(access_token):
        refresh_response = refresh_access_token(session, refresh_url, refresh_token, user_id)
        if refresh_response.status_code == 200:
            new_tokens = refresh_response.json()
            access_token = new_tokens.get('accessToken')
            refresh_token = new_tokens.get('refreshToken')
        else:
            raise HTTPException(status_code=refresh_response.status_code, detail="Failed to refresh access token")

    # Get regions
    regions_data = get_json_data(session, regions_url, access_token)
    if not regions_data:
        raise HTTPException(status_code=500, detail="Failed to get regions data")

    return regions_data

@app.get("/brands")
def get_brands():
    csv_file = 'credentials.csv'
    login_url = 'https://mapi.maicatech.com/auth/v2/login'
    refresh_url = 'https://mapi.maicatech.com/auth/refresh-token'
    regions_url = 'https://mapi.maicatech.com/group/regions'
    brands_url = 'https://mapi.maicatech.com/device/flowmeter/group/brands'

    # Read credentials from CSV
    email, password = read_credentials(csv_file)

    # Create a session
    session = requests.Session()

    # Log in to the website
    response = login(session, login_url, email, password)
    if response.status_code != 200:
        raise HTTPException(status_code=response.status_code, detail="Login failed")

    tokens = response.json()
    access_token = tokens.get('accessToken')
    refresh_token = tokens.get('refreshToken')
    user_id = tokens.get('userId')

    # Check if the access token is expired
    if is_token_expired(access_token):
        refresh_response = refresh_access_token(session, refresh_url, refresh_token, user_id)
        if refresh_response.status_code == 200:
            new_tokens = refresh_response.json()
            access_token = new_tokens.get('accessToken')
            refresh_token = new_tokens.get('refreshToken')
        else:
            raise HTTPException(status_code=refresh_response.status_code, detail="Failed to refresh access token")

    # Get regions
    regions_data = get_json_data(session, regions_url, access_token)
    if not regions_data:
        raise HTTPException(status_code=500, detail="Failed to get regions data")

    regions = [region['regionId'] for region in regions_data]

    # Prepare payload for brands request
    # Get the current date
    current_date = datetime.now()

    # Set start_date to the beginning of the current day
    start_date = current_date.replace(hour=0, minute=0, second=0, microsecond=0).isoformat() + "Z"

    # Set end_date to the end of the current day
    end_date = (current_date.replace(hour=23, minute=59, second=59, microsecond=999999) + timedelta(milliseconds=59)).isoformat() + "Z"

    payload = {
        'regionIds': regions,
        'startDate': start_date,
        'endDate': end_date,
        'dailyData': True
    }

    brands_data = post_json_data(session, brands_url, access_token, payload)
    if not brands_data:
        raise HTTPException(status_code=500, detail="Failed to get brands data")
    flattened_data = flatten_and_filter_data(brands_data)
    return {
        "flattened_data": flattened_data
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
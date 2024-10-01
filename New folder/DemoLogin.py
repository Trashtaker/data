import requests
import csv
import socket

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

# Function to log in without handling tokens
def login(session, login_url, email, password):
    payload = {
        'email': email,
        'password': password,
        'deviceType': 'PERSONAL_COMPUTER',
        'ipAddress': get_local_ip(),
        'operatingSystem': 'Windows'
    }
    print(f"Payload: {payload}")  # Print the payload for debugging
    response = session.get(login_url, data=payload)
    return response

# Main function
def main():
    csv_file = 'credentials.csv'
    login_url = 'https://app.maicatech.com/'  # Replace with the actual login URL

    # Read credentials from CSV
    email, password = read_credentials(csv_file)

    # Create a session
    session = requests.Session()

    # Log in to the website
    try:
        response = login(session, login_url, email, password)
        print(f"Status Code: {response.status_code}")
        print(f"Response Content: {response.text}")
        if response.status_code == 200:
            print("Login successful")
        else:
            print("Login failed")
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()
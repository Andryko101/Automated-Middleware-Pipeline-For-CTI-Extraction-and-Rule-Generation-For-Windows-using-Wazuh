import requests

url = "https://freshrss-ijkt.onrender.com/api/greader.php/accounts/ClientLogin"
payload = {
    "Email": "andrew",
    "Passwd": "freshrss"
}

response = requests.post(url, data=payload)
print(f"Status Code: {response.status_code}")
print(f"Response Body: {response.text}")
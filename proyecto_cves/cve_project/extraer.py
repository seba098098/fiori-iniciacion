import requests
import json

url = "https://www.cvedetails.com/api/v1/vulnerability/list"
headers = {
    "accept": "application/json",
    "Authorization": "Bearer 5eea6f8cb67b0a0cad6de44d6263f222acde2eee.eyJzdWIiOjEzMzMzLCJpYXQiOjE3NTM3MjAzMjIsImV4cCI6MTc1NjMzOTIwMCwia2lkIjoxLCJjIjoiNkQ5XC9vbThzcGpzdzRrbFZ2NlBQeE1jVXh5T255U0xuOTBTdFV5a2cxTE9VVnExZWNLNGlmOXk1dGZyckFOTGxzQ0hrRmcrc2dRPT0ifQ=="
}

params = {
    "page": 1,
    "size": 5  # puedes subir este número si quieres más resultados
}

response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    print("✅ Lista de CVEs:")
    print(json.dumps(response.json(), indent=2, ensure_ascii=False))
else:
    print(f"❌ Error {response.status_code}")
    print(response.text)

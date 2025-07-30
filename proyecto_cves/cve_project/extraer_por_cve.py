import requests
import json

# Cadena de CVEs
cadena_cves = "CVE-2025-54597,CVE-2024-3400,CVE-2023-23397,CVE-2002-000"
lista_cves = cadena_cves.split(",")

# Configuración
BASE_URL = "https://www.cvedetails.com/api/v1/vulnerability/cve-json"
HEADERS = {
    "accept": "application/json",
    "Authorization": "Bearer 5eea6f8cb67b0a0cad6de44d6263f222acde2eee.eyJzdWIiOjEzMzMzLCJpYXQiOjE3NTM3MjAzMjIsImV4cCI6MTc1NjMzOTIwMCwia2lkIjoxLCJjIjoiNkQ5XC9vbThzcGpzdzRrbFZ2NlBQeE1jVXh5T255U0xuOTBTdFV5a2cxTE9VVnExZWNLNGlmOXk1dGZyckFOTGxzQ0hrRmcrc2dRPT0ifQ=="
}

# Recorrer y consultar cada CVE
for cve_id in lista_cves:
    response = requests.get(BASE_URL, headers=HEADERS, params={"cveId": cve_id.strip()})
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Información de {cve_id}:")
        print(json.dumps(data, indent=2, ensure_ascii=False))
    elif response.status_code == 404:
        print(f"⚠️ No se encontró información para {cve_id}.")
    else:
        print(f"❌ Error {response.status_code} en {cve_id}: {response.text}")

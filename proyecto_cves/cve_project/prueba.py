import requests
import json
import urllib3
import time
import os

# 🔕 Silenciar advertencias por verify=False (solo si estás seguro)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIGURACIÓN ===
BASE_URL = "https://www.cvedetails.com/api/v1/vulnerability/search"
HEADERS = {
    "accept": "application/json",
    "Authorization": "Bearer 5eea6f8cb67b0a0cad6de44d6263f222acde2eee.eyJzdWIiOjEzMzMzLCJpYXQiOjE3NTM3MjAzMjIsImV4cCI6MTc1NjMzOTIwMCwia2lkIjoxLCJjIjoiNkQ5XC9vbThzcGpzdzRrbFZ2NlBQeE1jVXh5T255U0xuOTBTdFV5a2cxTE9VVnExZWNLNGlmOXk1dGZyckFOTGxzQ0hrRmcrc2dRPT0ifQ=="
}
LIMIT = 10000000
offset = 0
all_data = []
BACKUP_EVERY = 5000  # Guarda cada X registros
SLEEP_SECONDS = 15   # Tiempo entre peticiones (ajústalo si te bloquean)

# === INICIO DE DESCARGA ===
print("🚀 Iniciando descarga de CVEs...")

while True:
    url = f"{BASE_URL}?limit={LIMIT}&offset={offset}"
    print(f"🔄 Descargando offset: {offset}")

    try:
        response = requests.get(url, headers=HEADERS, verify=False)
    except Exception as e:
        print(f"❌ Error de conexión: {e}")
        print("⏳ Esperando 30 segundos y reintentando...")
        time.sleep(30)
        continue

    if response.status_code == 429:
        print("⏳ Límite de peticiones alcanzado (429). Esperando 60 segundos...")
        time.sleep(60)
        continue

    if response.status_code != 200:
        print(f"❌ Error en la solicitud: {response.status_code}")
        print(response.text)
        break

    data = response.json()
    results = data.get("results", [])

    if not results:
        print("✅ No quedan más registros.")
        break

    all_data.extend(results)
    offset += LIMIT

    # 💾 Guardar backup parcial cada X registros
    if offset % BACKUP_EVERY == 0:
        filename = f"cves_partial_{offset}.json"
        with open(filename, "w") as f:
            json.dump(all_data, f, indent=2)
        print(f"💾 Backup parcial guardado: {filename}")

    # Esperar para no sobrepasar el rate limit
    time.sleep(SLEEP_SECONDS)

# === GUARDAR TODO ===
final_file = "cves_search_results_all.json"
with open(final_file, "w") as f:
    json.dump(all_data, f, indent=2)

print(f"✅ Descarga finalizada. Total registros: {len(all_data)}")
print(f"📁 Archivo completo guardado como: {final_file}")

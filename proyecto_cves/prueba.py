import requests
import time
import os
import json
import csv
from datetime import datetime

# ==== CONFIGURACIÓN ====
GITHUB_TOKEN = ""  # Reemplaza con tu token válido
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
BASE_URL = "https://api.github.com"
BASE_PATH = "cves"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}
MAX_CVES = 20  # ← Cambia esto para aumentar/disminuir los CVEs procesados

# Archivos de salida
OUTPUT_DIR = "cves_data"
JSON_FILE = os.path.join(OUTPUT_DIR, "consolidado.json")
CSV_FILE = os.path.join(OUTPUT_DIR, "consolidado.csv")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==== FUNCIONES ====
def github_api_request(url, params=None):
    while True:
        try:
            response = requests.get(url, headers=HEADERS, params=params)
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers and response.headers['X-RateLimit-Remaining'] == '0':
                reset = int(response.headers['X-RateLimit-Reset'])
                wait = reset - time.time()
                print(f"Rate limit alcanzado. Esperando {int(wait)} segundos...")
                time.sleep(wait + 1)
                continue
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error al consultar {url}: {e}")
            time.sleep(5)

def list_directory(path):
    url = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/contents/{path}?ref={BRANCH}"
    return github_api_request(url)

def download_file(download_url):
    response = requests.get(download_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()

def save_json(data):
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def save_csv(data):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["cveId", "datePublished", "assignerShortName", "cvssMetrics", "description"])

        for item in data:
            metadata = item.get("cveMetadata", {})
            cve_id = metadata.get("cveId", "")
            date_published = metadata.get("datePublished", "")
            assigner = metadata.get("assignerShortName", "")

            # Aplana CVSS
            metrics = item.get("containers", {}).get("cna", {}).get("metrics", [])
            cvss_text = ", ".join([json.dumps(m) for m in metrics]) if metrics else ""

            # Aplana descripción
            descriptions = item.get("containers", {}).get("cna", {}).get("descriptions", [])
            description_text = ", ".join([d.get("value", "") for d in descriptions]) if descriptions else ""

            writer.writerow([cve_id, date_published, assigner, cvss_text, description_text])

# ==== PROCESAMIENTO PRINCIPAL ====
def process_repository():
    current_year = datetime.now().year
    years = [str(year) for year in range(1999, current_year + 1)]
    collected = []
    seen_ids = set()

    for year in years:
        print(f"\nProcesando año {year}...")
        try:
            year_folders = list_directory(f"{BASE_PATH}/{year}")
        except Exception as e:
            print(f"  ⚠ Error en el año {year}: {e}")
            continue

        for folder in year_folders:
            if folder["type"] != "dir":
                continue

            try:
                files = list_directory(folder["path"])
            except Exception as e:
                print(f"  ⚠ Error al listar {folder['path']}: {e}")
                continue

            for file in files:
                if file["type"] != "file" or not file["name"].endswith(".json"):
                    continue

                cve_id = file["name"].replace(".json", "")
                if cve_id in seen_ids:
                    continue

                try:
                    cve_data = download_file(file["download_url"])
                    collected.append(cve_data)
                    seen_ids.add(cve_id)
                    print(f"  ✅ {cve_id} añadido ({len(collected)}/{MAX_CVES})")

                    if len(collected) >= MAX_CVES:
                        save_json(collected)
                        save_csv(collected)
                        print(f"\n✅ Finalizado: {len(collected)} CVEs guardados en JSON y CSV")
                        return

                except Exception as e:
                    print(f"  ❌ Error en {file['path']}: {e}")
                    continue

    print(f"\n⚠ Se alcanzó el final sin llegar a {MAX_CVES} CVEs.")
    save_json(collected)
    save_csv(collected)

# ==== EJECUCIÓN ====
if __name__ == "__main__":
    process_repository()

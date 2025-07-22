import requests
import time
import os
import json
from datetime import datetime

# ==== CONFIGURACIÓN ====
GITHUB_TOKEN = "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"  # <-- Coloca tu token válido aquí
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
BASE_URL = "https://api.github.com"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Carpeta y archivo de salida
OUTPUT_DIR = "cves_data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "consolidado.json")
os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==== FUNCIONES ====

def github_api_request(url, params=None):
    """Hace una solicitud a la API de GitHub, manejando errores y límites"""
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


def get_all_json_files_from_repo():
    """Usa la API /git/trees para obtener todos los archivos JSON en cves/"""
    print("🔍 Obteniendo árbol completo del repositorio...")

    # Paso 1: Obtener SHA del branch principal
    url_branch = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/branches/{BRANCH}"
    branch_info = github_api_request(url_branch)
    sha = branch_info["commit"]["commit"]["tree"]["sha"]

    # Paso 2: Obtener árbol de archivos completo de forma recursiva
    url_tree = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{sha}?recursive=1"
    tree = github_api_request(url_tree)

    # Filtrar archivos .json dentro de cves/
    json_files = [
        item for item in tree.get("tree", [])
        if item["path"].startswith("cves/") and item["path"].endswith(".json") and item["type"] == "blob"
    ]

    print(f"📄 Se encontraron {len(json_files)} archivos JSON.")
    return json_files


def download_file_from_raw(path):
    """Descarga el archivo desde la URL cruda de GitHub"""
    raw_url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{path}"
    response = requests.get(raw_url, headers=HEADERS)
    response.raise_for_status()
    return response.json()


def load_existing_data():
    """Carga datos ya descargados previamente (si existe)"""
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_consolidated_data(data):
    """Guarda todos los CVEs en un solo archivo consolidado"""
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


# ==== PROCESAMIENTO PRINCIPAL ====

def process_repository():
    json_files = get_all_json_files_from_repo()
    consolidated_data = load_existing_data()

    existing_ids = {
        entry.get("cveMetadata", {}).get("cveId")
        for entry in consolidated_data if "cveMetadata" in entry
    }

    print("🚀 Comenzando descarga de archivos JSON...")
    for i, file in enumerate(json_files, 1):
        cve_id = file["path"].split("/")[-1].replace(".json", "")
        if cve_id in existing_ids:
            continue

        try:
            cve_data = download_file_from_raw(file["path"])
            consolidated_data.append(cve_data)
            existing_ids.add(cve_id)

            if len(consolidated_data) % 100 == 0:
                save_consolidated_data(consolidated_data)
                print(f"   + Guardados {len(consolidated_data)} registros...")

        except Exception as e:
            print(f"   ! Error con {file['path']}: {e}")
            continue

    save_consolidated_data(consolidated_data)
    print(f"\n✅ Proceso completado. Se guardaron {len(consolidated_data)} CVEs en '{OUTPUT_FILE}'.")


# ==== EJECUCIÓN ====
if __name__ == "__main__":
    process_repository()

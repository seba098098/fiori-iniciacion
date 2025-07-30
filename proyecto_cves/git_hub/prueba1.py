import requests
import time
import os
import json
import csv
from datetime import datetime

# ==== CONFIGURACIÓN ====
GITHUB_TOKEN = ""
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main" 
BASE_URL = "https://api.github.com"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Rutas
OUTPUT_DIR = "."
ARCHIVOS_DIR = os.path.join(OUTPUT_DIR, "descargas_cves")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "consolidado.json")
SHA_FILE = os.path.join(OUTPUT_DIR, "registro_sha.csv")

os.makedirs(ARCHIVOS_DIR, exist_ok=True)

# ==== FUNCIONES AUXILIARES ====


def github_api_request(url, params=None, retries=3):
    for attempt in range(retries):
        try:
            response = requests.get(url, headers=HEADERS, params=params)
            if response.status_code == 403 and response.headers.get('X-RateLimit-Remaining') == '0':
                reset = int(response.headers['X-RateLimit-Reset'])
                wait = reset - time.time()
                print(f"⏳ Rate limit alcanzado. Esperando {int(wait)} segundos...")
                time.sleep(wait + 1)
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"⚠️ Error al consultar {url} (intento {attempt+1}/{retries}): {e}")
            time.sleep(5)
    raise Exception(f"❌ No se pudo obtener datos de la API después de {retries} intentos: {url}")


def get_all_json_files_from_repo():
    print("🔍 Obteniendo árbol del repositorio por año...")

    try:
        url_branch = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/branches/{BRANCH}"
        branch_info = github_api_request(url_branch)
        root_sha = branch_info["commit"]["commit"]["tree"]["sha"]

        url_root = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{root_sha}"
        root_tree = github_api_request(url_root)

        cves_node = next((item for item in root_tree["tree"] if item["path"] == "cves" and item["type"] == "tree"), None)
        if not cves_node:
            raise Exception("No se encontró el directorio 'cves'.")

        url_cves = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{cves_node['sha']}"
        cves_tree = github_api_request(url_cves)

        json_files = []

        for year_node in cves_tree["tree"]:
            year = year_node["path"]
            if year_node["type"] != "tree" or not year.isdigit():
                continue

            print(f"📂 Procesando año: {year}")
            url_year = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{year_node['sha']}"
            year_tree = github_api_request(url_year)

            for folder_node in year_tree["tree"]:
                if folder_node["type"] != "tree":
                    continue

                url_folder = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{folder_node['sha']}"
                folder_tree = github_api_request(url_folder)

                for file_node in folder_tree["tree"]:
                    if file_node["type"] == "blob" and file_node["path"].endswith(".json"):
                        full_path = f"cves/{year}/{folder_node['path']}/{file_node['path']}"
                        json_files.append({"path": full_path, "sha": file_node["sha"]})
    except Exception as e:
        print(f"❌ Error al procesar el árbol del repositorio: {e}")
        return []

    print(f"📄 Se encontraron {len(json_files)} archivos JSON.")
    return json_files


def load_sha_registry():
    if not os.path.exists(SHA_FILE):
        return {}
    sha_registry = {}
    try:
        with open(SHA_FILE, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                sha_registry[row["path"]] = row["sha"]
    except Exception as e:
        print(f"⚠️ Error al leer {SHA_FILE}: {e}")
    return sha_registry


def save_sha_registry(sha_dict):
    try:
        with open(SHA_FILE, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "sha", "fecha"])
            writer.writeheader()
            for path, (sha, fecha) in sha_dict.items():
                writer.writerow({"path": path, "sha": sha, "fecha": fecha})
    except Exception as e:
        print(f"❌ Error al guardar el registro de SHAs: {e}")


def download_file_to_disk(path, local_path):
    raw_url = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{path}"
    try:
        response = requests.get(raw_url, headers=HEADERS)
        response.raise_for_status()
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write(response.text)
        return json.loads(response.text)
    except Exception as e:
        print(f"❌ Error al descargar o parsear {path}: {e}")
        raise


def load_existing_data():
    if os.path.exists(OUTPUT_FILE):
        try:
            with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"⚠️ Error al leer {OUTPUT_FILE}: {e}")
    return []


def save_consolidated_data(data):
    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"❌ Error al guardar {OUTPUT_FILE}: {e}")


# ==== PROCESAMIENTO PRINCIPAL ====
def process_repository():
    try:
        json_files = get_all_json_files_from_repo()
        if not json_files:
            print("🚫 No se encontraron archivos JSON. Terminando proceso.")
            return

        consolidated_data = load_existing_data()
        sha_registry = load_sha_registry()
        updated_sha_registry = {}

        nuevos, modificados, sin_cambios = [], [], []

        print("🚀 Comenzando descarga de archivos JSON...")

        for i, file in enumerate(json_files, 1):
            path = file["path"]
            sha = file["sha"]
            cve_id = path.split("/")[-1].replace(".json", "")

            if path not in sha_registry:
                nuevos.append(path)
            elif sha_registry[path] != sha:
                modificados.append(path)
            else:
                sin_cambios.append(path)
                updated_sha_registry[path] = (sha, datetime.now().isoformat())
                continue

            try:
                local_path = os.path.join(ARCHIVOS_DIR, path.replace("/", os.sep))
                cve_data = download_file_to_disk(path, local_path)

                index = next((i for i, entry in enumerate(consolidated_data)
                              if entry.get("cveMetadata", {}).get("cveId") == cve_id), None)

                if index is not None:
                    consolidated_data[index] = cve_data
                    print(f"🔄 CVE actualizado: {cve_id}")
                else:
                    consolidated_data.append(cve_data)
                    print(f"➕ CVE agregado: {cve_id}")

                updated_sha_registry[path] = (sha, datetime.now().isoformat())

                if len(consolidated_data) % 100 == 0:
                    save_consolidated_data(consolidated_data)
                    print(f"💾 Guardados {len(consolidated_data)} registros...")

            except Exception as e:
                print(f"⚠️ Error procesando {path}: {e}")
                continue

        save_consolidated_data(consolidated_data)
        save_sha_registry(updated_sha_registry)

        print(f"\n✅ Proceso completado.")
        print(f"➕ Nuevos: {len(nuevos)} | 🔄 Modificados: {len(modificados)} | ✅ Sin cambios: {len(sin_cambios)}")
        print(f"📦 Total consolidado: {len(consolidated_data)} registros en '{OUTPUT_FILE}'")

    except Exception as e:
        print(f"💥 Error crítico en el procesamiento del repositorio: {e}")


# ==== EJECUCIÓN ====
if __name__ == "__main__":
    process_repository()

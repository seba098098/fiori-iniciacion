import requests
import time
import os
import csv
from datetime import datetime

# ==== CONFIGURACIÓN ====
GITHUB_TOKEN = ""
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
BASE_URL = "https://api.github.com"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Archivo de salida
CSV_FILE = "shas_por_archivo.csv"

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
    raise Exception(f"❌ No se pudo obtener datos de la API: {url}")

def obtener_shas_por_archivo():
    print("🔍 Obteniendo árbol del repositorio para todos los años...")

    resultados = []

    try:
        # Obtener SHA raíz del branch
        url_branch = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/branches/{BRANCH}"
        branch_info = github_api_request(url_branch)
        root_sha = branch_info["commit"]["commit"]["tree"]["sha"]

        # Obtener árbol raíz
        url_root = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{root_sha}"
        root_tree = github_api_request(url_root)

        cves_node = next((item for item in root_tree["tree"] if item["path"] == "cves" and item["type"] == "tree"), None)
        if not cves_node:
            raise Exception("No se encontró el directorio 'cves'.")

        url_cves = f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{cves_node['sha']}"
        cves_tree = github_api_request(url_cves)

        for year_node in cves_tree["tree"]:
            year = year_node["path"]
            if year_node["type"] != "tree" or not year.isdigit():
                continue
            if int(year) < 1999:
                continue

            print(f"📂 Explorando año: {year}")
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
                        resultados.append({
                            "path": full_path,
                            "sha": file_node["sha"],
                            "anio": year
                        })

    except Exception as e:
        print(f"❌ Error al procesar árbol del repositorio: {e}")

    return resultados

def guardar_en_csv(data):
    try:
        with open(CSV_FILE, "w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["path", "sha", "anio"])
            writer.writeheader()
            writer.writerows(data)
        print(f"✅ SHA guardados en: {CSV_FILE} ({len(data)} archivos)")
    except Exception as e:
        print(f"❌ Error al guardar CSV: {e}")

if __name__ == "__main__":
    shas = obtener_shas_por_archivo()
    guardar_en_csv(shas)

import requests
import os
import json
import csv
from datetime import datetime

# ========== CONFIGURACIÓN ==========
GITHUB_TOKEN = ""  # Opcional: coloca aquí tu token si lo necesitas
REPO_OWNER = "CVEProject"
REPO_NAME = "cvelistV5"
BRANCH = "main"
BASE_URL = "https://api.github.com"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}

# Carpetas locales
DATA_FOLDER = "descargas_cves"
SHA_FILE = "sha.csv"


# ========== FUNCIONES AUXILIARES ==========
def github_api_request(url):
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise RuntimeError(f"Error al hacer la solicitud HTTP: {e}")
    except json.JSONDecodeError:
        raise RuntimeError("La respuesta no es un JSON válido")


def leer_sha_previos():
    if not os.path.exists(SHA_FILE):
        return {}
    try:
        with open(SHA_FILE, "r", newline="", encoding="utf-8") as file:
            return {row["path"]: row["sha"] for row in csv.DictReader(file)}
    except Exception as e:
        print(f"⚠️ Error al leer archivo de SHAs previos: {e}")
        return {}


def guardar_sha(shas):
    try:
        with open(SHA_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["path", "sha", "anio"])
            writer.writeheader()
            writer.writerows(shas)
    except Exception as e:
        print(f"❌ Error al guardar SHAs: {e}")


# ========== OBTENCIÓN DE SHAs ==========
def obtener_shas_actualizados():
    print("🔍 Obteniendo árbol del repositorio para todos los años...")
    resultados = []
    total_json_files = 0
    try:
        # Obtener SHA raíz
        branch_info = github_api_request(f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/branches/{BRANCH}")
        root_sha = branch_info["commit"]["commit"]["tree"]["sha"]

        root_tree = github_api_request(f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{root_sha}")
        cves_node = next((item for item in root_tree["tree"] if item["path"] == "cves" and item["type"] == "tree"), None)
        if not cves_node:
            raise Exception("No se encontró el directorio 'cves' en el repositorio")

        cves_tree = github_api_request(f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{cves_node['sha']}")
        for year_node in cves_tree["tree"]:
            year = year_node["path"]
            if year_node["type"] != "tree" or not year.isdigit() or int(year) < 1999:
                continue

            print(f"📂 Año: {year}")
            year_tree = github_api_request(f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{year_node['sha']}")
            for folder_node in year_tree["tree"]:
                if folder_node["type"] != "tree":
                    continue
                folder_tree = github_api_request(f"{BASE_URL}/repos/{REPO_OWNER}/{REPO_NAME}/git/trees/{folder_node['sha']}")
                for file_node in folder_tree["tree"]:
                    if file_node["type"] == "blob" and file_node["path"].endswith(".json"):
                        resultados.append({
                            "path": f"cves/{year}/{folder_node['path']}/{file_node['path']}",
                            "sha": file_node["sha"],
                            "anio": year
                        })
                        total_json_files += 1
        print(f"📄 Se encontraron {total_json_files} archivos JSON.")
    except Exception as e:
        print(f"❌ Error obteniendo SHAs: {e}")
    return resultados



# ========== DESCARGA DE ARCHIVOS ==========
def descargar_archivos(shas_actuales, shas_previos):
    nuevos_shas = []
    archivos_nuevos = []
    archivos_actualizados = []

    for item in shas_actuales:
        path, sha, anio = item["path"], item["sha"], item["anio"]
        previo_sha = shas_previos.get(path)

        if previo_sha == sha:
            continue  # Sin cambios

        accion = "🆕 Nuevo" if previo_sha is None else "♻️ Actualizado"
        print(f"{accion} → {path}")

        url_raw = f"https://raw.githubusercontent.com/{REPO_OWNER}/{REPO_NAME}/{BRANCH}/{path}"
        try:
            response = requests.get(url_raw, timeout=10)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"⚠️ Error al descargar o parsear {path}: {e}")
            continue

        try:
            local_path = os.path.join(DATA_FOLDER, path)
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            with open(local_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)

            nuevos_shas.append(item)
            if previo_sha is None:
                archivos_nuevos.append(path)
            else:
                archivos_actualizados.append(path)
        except Exception as e:
            print(f"❌ Error al guardar {path}: {e}")

    print(f"\n✅ Archivos nuevos: {len(archivos_nuevos)}")
    print(f"🔁 Archivos actualizados: {len(archivos_actualizados)}")
    return nuevos_shas


# ========== CONSOLIDAR JSONS ==========
def generar_consolidado_json(base_path):
    print("\n📦 Generando consolidado de JSONs...")
    consolidado = []
    errores = []

    for root, _, files in os.walk(base_path):
        for file in files:
            if not file.endswith(".json") or file == "consolidado.json":
                continue
            full_path = os.path.join(root, file)
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        if "containers" in data and isinstance(data["containers"], list):
                            consolidado.extend(data["containers"])
                        else:
                            consolidado.append(data)
                    elif isinstance(data, list):
                        consolidado.extend(data)
                    else:
                        raise ValueError("Estructura JSON no soportada")
            except Exception as e:
                errores.append((full_path, str(e)))
                print(f"⚠️ Archivo ignorado: {file} -> {e}")

    try:
        output_path = os.path.join(base_path, "consolidado.json")
        with open(output_path, "w", encoding="utf-8") as f_out:
            json.dump(consolidado, f_out, indent=2, ensure_ascii=False)
        print(f"\n✅ Consolidado guardado: {output_path}")
        print(f"📄 Documentos válidos: {len(consolidado)}")
        if errores:
            print(f"⚠️ Archivos ignorados por errores: {len(errores)}")
            print("📂 Lista de archivos JSON no válidos:")
            for ruta, err in errores:
                print(f" - {ruta} -> {err}")
    except Exception as e:
        print(f"❌ Error al guardar consolidado: {e}")



# ========== MAIN ==========
def main():
    print("🚀 Iniciando proceso de sincronización CVEs...")
    shas_previos = leer_sha_previos()
    shas_actuales = obtener_shas_actualizados()

    if not shas_actuales:
        print("🛑 No se pudo recuperar la lista de SHAs. Abortando.")
        return

    nuevos = descargar_archivos(shas_actuales, shas_previos)
    if nuevos:
        guardar_sha(shas_actuales)
        print(f"✅ Archivos nuevos/actualizados: {len(nuevos)}")
    else:
        print("🟢 No hay archivos nuevos. Todo está actualizado.")

    generar_consolidado_json(DATA_FOLDER)


if __name__ == "__main__":
    main()

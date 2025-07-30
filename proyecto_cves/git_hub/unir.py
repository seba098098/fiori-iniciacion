import os
import json

# === CONFIGURACIÓN ===
CARPETA_JSONS = "descargas_cves"  # Carpeta raíz donde están los JSON descargados
ARCHIVO_SALIDA = "consolidado.json"

def es_json_valido(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"⚠️ Archivo ignorado por error de formato JSON: {path} ({e})")
        return None

def unir_jsons():
    datos_consolidados = []
    total_archivos = 0
    json_validos = 0

    for root, _, files in os.walk(CARPETA_JSONS):
        for file in files:
            if file.endswith(".json"):
                total_archivos += 1
                ruta = os.path.join(root, file)
                contenido = es_json_valido(ruta)
                if contenido is not None:
                    datos_consolidados.append(contenido)
                    json_validos += 1

    try:
        with open(ARCHIVO_SALIDA, "w", encoding="utf-8") as f:
            json.dump(datos_consolidados, f, indent=2)
        print(f"\n✅ Unión completa.")
        print(f"✔️ JSON válidos unidos: {json_validos}")
        print(f"❌ JSON ignorados: {total_archivos - json_validos}")
        print(f"📦 Archivo creado: {ARCHIVO_SALIDA}")
    except Exception as e:
        print(f"❌ Error al guardar archivo consolidado: {e}")

if __name__ == "__main__":
    unir_jsons()

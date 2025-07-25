import json
import os
import sys

# Cambia la ruta si tu archivo está en otro lugar
RUTA_CONSOLIDADO = os.path.join("descargas_cves", "consolidado.json")

def validar_consolidado(ruta):
    try:
        with open(ruta, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Si llegó aquí, el JSON es válido
        elementos = len(data) if isinstance(data, list) else 1
        print(f"✅ JSON válido. Elementos encontrados: {elementos}")
    except FileNotFoundError:
        print(f"❌ No se encontró el archivo: {ruta}")
    except json.JSONDecodeError as e:
        print(f"❌ JSON malformado: {e}")
    except Exception as e:
        print(f"⚠️ Error inesperado: {e}")

if __name__ == "__main__":
    validar_consolidado(RUTA_CONSOLIDADO)

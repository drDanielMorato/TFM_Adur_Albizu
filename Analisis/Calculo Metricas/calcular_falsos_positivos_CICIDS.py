import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as json_file:
        return json.load(json_file)


def evaluar_predicciones( predictions: list):
    fp = len(predictions)

    # print(f"ataques d: {ataques_detectados}")
    return {
        "FP": fp
    }


def main():
    parser = argparse.ArgumentParser(
        description="Cuenta los falsos positivos en la predicción del dataset cicids2017"
    )
    parser.add_argument("archivo_predicciones", help="Ruta al resultado del detector.")
    
    args = parser.parse_args()

    results = evaluar_predicciones(load_json(args.archivo_predicciones))

    print()
    print(f"FP:{results['FP']}")


if __name__ == "__main__":
    main()
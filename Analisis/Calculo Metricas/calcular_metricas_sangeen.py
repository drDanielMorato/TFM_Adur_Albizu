import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_json(path: str):
    with open(path, "r", encoding="utf-8") as json_file:
        return json.load(json_file)


def evaluar_predicciones(ground_truth: dict, predictions: list, tolerance: float):
    predictions_by_file = defaultdict(list)
    for prediction in predictions:
        predictions_by_file[prediction["file"]].append(prediction)

    ataques_detectados = set()
    prediccion_acertada = set()

    for file_path, attacker_ips in ground_truth.items():
        for prediction_index, prediction in enumerate(predictions_by_file[file_path]):
            attacker_time = attacker_ips.get(prediction["ipSource"])

            ip_prediccion = prediction["ipSource"]
            if attacker_time is None:
                print(f"la ip {ip_prediccion} no está en el ground truth, en {file_path}")
                continue

            time_difference = abs(float(prediction["startTime"]) - float(attacker_time))
            if time_difference <= tolerance:
                ataques_detectados.add(file_path)
                prediccion_acertada.add((file_path, prediction_index))
            else:
                print(f"para la ip {ip_prediccion} se ha roto la tolerancia temporal")

    false_positives = sum(
        1
        for file_path, file_predictions in predictions_by_file.items()
        for prediction_index, _ in enumerate(file_predictions)
        if (file_path, prediction_index) not in prediccion_acertada
    )

    positives = len(ground_truth)
    true_positives = len(ataques_detectados)
    false_negatives = positives - true_positives

    matched_prediction_count = len(prediccion_acertada)
    # prediction_precision = (
    #     matched_prediction_count / len(predictions) if predictions else 0.0
    # )
    # attack_recall = true_positives / positives if positives else 0.0

    number_ip_ground_truth_file = sum([1 for _, attacker_ips in ground_truth.items()
                                   for _ in attacker_ips])

    # print(f"ataques d: {ataques_detectados}")
    return {
        "number_of_predictions" : len(predictions),
        "positives": positives,
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "false_positives": false_positives,
        "matched_predictions": matched_prediction_count,
        # "prediction_precision": prediction_precision,
        # "attack_recall": attack_recall,
        "undetected_files": sorted(set(ground_truth) - ataques_detectados),
        "number_ip_ground_truth_file": number_ip_ground_truth_file
    }


def main():
    parser = argparse.ArgumentParser(
        description="Comparar cualquiera de los métodos contra el ground truth del dataset Sangeen"
    )
    parser.add_argument("archivo_predicciones", help="Ruta al resultado del detector.")
    parser.add_argument("ground_truth", help="Ruta a groundTruthSangeen.json.")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=1,
        help="Timestamp máximo de diferencia (default: 1 s).",
    )
    args = parser.parse_args()

    if args.tolerance < 0:
        raise ValueError("El timestamp de tolerancia debe ser positivo.")

    results = evaluar_predicciones(
        load_json(args.ground_truth), load_json(args.archivo_predicciones), args.tolerance
    )

    print()
    print(f"Number of ips in ground truth file: {results['number_ip_ground_truth_file']}")
    print(f"Number of predictions (IPs): {results['number_of_predictions']}")
    print(f"Matched predictions: {results['matched_predictions']}")
    print(f"P (attacks in ground truth): {results['positives']}")
    print(f"TP (detected attacks): {results['true_positives']}")
    print(f"FN (undetected attacks): {results['false_negatives']}")
    print(f"FP (unmatched predicted conversations): {results['false_positives']}")
    # print(f"Prediction precision: {results['prediction_precision']:.4f}")
    # print(f"Attack recall: {results['attack_recall']:.4f}")
    print("Undetected files:")
    for file_path in results["undetected_files"]:
        print(f"  {file_path}")


if __name__ == "__main__":
    main()
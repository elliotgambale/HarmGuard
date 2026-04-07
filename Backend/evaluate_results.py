import csv
import sys


def to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python evaluate_results.py path/to/results.csv")
        return 1

    path = sys.argv[1]
    tp = fp = tn = fn = 0

    with open(path, newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        for row in reader:
            actual = to_bool(row["actual_label"])
            predicted = to_bool(row["is_harmful"])

            if actual and predicted:
                tp += 1
            elif not actual and predicted:
                fp += 1
            elif actual and not predicted:
                fn += 1
            else:
                tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0

    print(f"TP={tp} FP={fp} TN={tn} FN={fn}")
    print(f"Precision={precision:.3f}")
    print(f"Recall={recall:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

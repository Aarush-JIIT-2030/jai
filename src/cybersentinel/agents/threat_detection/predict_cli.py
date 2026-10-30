"""Batch inference CLI for an existing Agent 1 artifact."""
import argparse, json
from pathlib import Path
import pandas as pd
from .model import ThreatDetectionModel

def predict_csv(model_path, input_csv, output_csv):
    frame = pd.read_csv(input_csv, low_memory=False)
    predictions = pd.DataFrame(ThreatDetectionModel.load(model_path).predict_frame(frame))
    path = Path(output_csv)
    path.parent.mkdir(parents=True, exist_ok=True)
    predictions.to_csv(path, index=False)
    return len(predictions)

def main():
    parser = argparse.ArgumentParser(description="Batch predict with CyberSentinel Agent 1.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--input-csv", required=True)
    parser.add_argument("--output-csv", default="reports/generated/threat_predictions.csv")
    args = parser.parse_args()
    count = predict_csv(args.model, args.input_csv, args.output_csv)
    print(json.dumps({"status": "success", "predictions": count, "output": args.output_csv}, indent=2))

if __name__ == "__main__":
    main()

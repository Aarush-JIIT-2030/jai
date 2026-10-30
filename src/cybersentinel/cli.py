"""CyberSentinel CLI; inference and training remain offline and dataset-driven."""
import argparse, json

def main():
    parser = argparse.ArgumentParser(prog="cybersentinel",
        description="Offline network-flow analysis; no live traffic or firewall actions.")
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train-threat", help="Train Agent 1.")
    train.add_argument("--train-csv", required=True); train.add_argument("--label-column", required=True)
    train.add_argument("--model-out", default="models/threat_detection.joblib"); train.add_argument("--label-map")
    train.add_argument("--validation-csv"); train.add_argument("--validation-label-column")
    train.add_argument("--backend", choices=["random_forest", "xgboost"], default="random_forest")
    train.add_argument("--n-estimators", type=int, default=400); train.add_argument("--random-state", type=int, default=42)
    train.add_argument("--report-out", default="reports/generated/threat_detection_training.json")
    evaluate = sub.add_parser("evaluate-threat", help="Evaluate saved Agent 1.")
    evaluate.add_argument("--model", required=True); evaluate.add_argument("--validation-csv", required=True)
    evaluate.add_argument("--label-column", required=True); evaluate.add_argument("--label-map")
    evaluate.add_argument("--report-out", default="reports/generated/threat_detection_evaluation.json")
    predict = sub.add_parser("predict-threat", help="Batch predict a CSV.")
    predict.add_argument("--model", required=True); predict.add_argument("--input-csv", required=True)
    predict.add_argument("--output-csv", default="reports/generated/threat_predictions.csv")
    args = parser.parse_args()
    if args.command == "train-threat":
        from cybersentinel.agents.threat_detection.train import train_from_csv
        result = train_from_csv(args.train_csv, args.label_column, args.model_out, args.label_map,
            args.validation_csv, args.validation_label_column, args.backend, args.n_estimators,
            args.random_state, args.report_out)
    elif args.command == "evaluate-threat":
        from cybersentinel.agents.threat_detection.evaluate import evaluate_csv
        result = evaluate_csv(args.model, args.validation_csv, args.label_column, args.label_map, args.report_out)
    else:
        from cybersentinel.agents.threat_detection.predict_cli import predict_csv
        count = predict_csv(args.model, args.input_csv, args.output_csv)
        result = {"status": "success", "predictions": count, "output": args.output_csv}
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()

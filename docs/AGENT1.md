# Agent 1 — Threat Detection

Member 2 owns this supervised-learning workstream.

## Install

    pip install -e ".[dev,ml]"

Optional XGBoost experiment:

    pip install -e ".[ml,xgboost]"

## Label mapping is organiser-controlled

If the CSV already uses BENIGN, BRUTE_FORCE, DOS, DDOS and PORT_SCAN, no mapping file is needed. If it uses original attack labels, create a JSON object mapping each exact source label to the benchmark class using the organisers' supplied mapping. No fuzzy matching or guessed attack mappings are performed. Any placeholder must be replaced with the organiser's actual mapping.

## Train and evaluate

    python -m cybersentinel.agents.threat_detection.train --train-csv data/raw/train.csv --label-column Label --label-map data/raw/organiser-label-map.json --validation-csv data/raw/validation.csv --model-out models/threat_detection.joblib --report-out reports/generated/threat_detection_training.json

The validation file is evaluation-only. Preprocessing and the classifier are fitted on training data only. Omit --label-map only if all labels are already canonical benchmark labels.

## XGBoost experiment

Add --backend xgboost after installing the optional dependency. Random Forest is the default baseline and uses balanced subsampling.

## Re-evaluate and batch predict

    python -m cybersentinel.agents.threat_detection.evaluate --model models/threat_detection.joblib --validation-csv data/raw/validation.csv --label-column Label --label-map data/raw/organiser-label-map.json
    python -m cybersentinel.agents.threat_detection.predict_cli --model models/threat_detection.joblib --input-csv data/raw/unlabelled-flows.csv --output-csv reports/generated/threat_predictions.csv

Each prediction contains agent, predicted_class, confidence and status. Confidence is the maximum predict_proba value from the fitted model; it is not calibrated confidence.

## Design limitations

- Flow ID, source/destination IP and timestamp identifiers are excluded to reduce memorisation. Numeric flow measurements and ports remain eligible.
- Non-numeric columns are excluded; numeric-like values are coerced. Infinite values become missing and are median-imputed from training data.
- Constant columns are removed using training data only.
- Training must contain all five benchmark classes.
- No benchmark performance is claimed until the official organiser data is evaluated. Synthetic tests verify software behavior only.

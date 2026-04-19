# Unified Cybersecurity Detection Project

This project trains one unified binary classifier across heterogeneous cybersecurity telemetry sources:

- `UNSW_NB15_training-set.parquet`
- `UNSW_NB15_testing-set.parquet`
- `CIC-IDS-2017/*.csv`
- `modsec-learn-dataset/*.json`
- `Firewall/*.csv`

The pipeline:

1. Discovers all required datasets automatically.
2. Normalizes each source into the unified schema:
   - `src_ip`
   - `dst_ip`
   - `src_port`
   - `dst_port`
   - `protocol`
   - `bytes`
   - `packets`
   - `duration`
   - `http_method`
   - `uri`
   - `label`
3. Engineers mandatory cross-source features.
4. Trains XGBoost and Random Forest candidates.
5. Selects the better model by validation F1.
6. Evaluates on a held-out test split.
7. Saves model artifacts and inference assets.

## Setup

```bash
pip install -r requirements.txt
```

## Train

```bash
python main.py train
```

Optional:

```bash
python main.py train --config configs/train_config.json --data-root ..
```

## Evaluate

This uses the persisted held-out test split in `artifacts/test_dataset.parquet`.

```bash
python main.py evaluate
```

## Predict

Input can be:

- a JSON object with unified schema fields
- a list of JSON objects
- a list of payload strings for web request inference

Example:

```bash
python main.py predict --input sample.json
```

Optional:

```bash
python main.py predict --input sample.json --output predictions.json
```

## Saved Artifacts

Training writes:

- `artifacts/model.pkl`
- `artifacts/feature_builder.pkl`
- `artifacts/encoders.json`
- `artifacts/schema_metadata.json`
- `artifacts/feature_list.json`
- `artifacts/training_summary.json`
- `artifacts/test_dataset.parquet`
- `artifacts/evaluation.json`
- `artifacts/classification_report.txt`
- `artifacts/confusion_matrix.csv`
- `artifacts/feature_importance.csv`

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

from src.inference.predictor import CybersecurityPredictor
from src.loaders.data_loader import UnifiedDatasetLoader
from src.models.artifacts import load_runtime_artifacts, save_training_artifacts
from src.models.trainer import ModelTrainer
from src.utils.common import dumps_json, ensure_directory, set_global_seed
from src.utils.config import load_config
from src.utils.logging_utils import setup_logging


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Unified cybersecurity detection pipeline")
    subparsers = parser.add_subparsers(dest="command", required=True)

    train_parser = subparsers.add_parser("train", help="Load data, train the unified model, and persist artifacts.")
    train_parser.add_argument("--config", default="configs/train_config.json")
    train_parser.add_argument("--data-root", default=None)
    train_parser.add_argument("--artifacts-dir", default=None)

    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate the saved model on the persisted test split.")
    evaluate_parser.add_argument("--config", default="configs/train_config.json")
    evaluate_parser.add_argument("--data-root", default=None)
    evaluate_parser.add_argument("--artifacts-dir", default=None)

    predict_parser = subparsers.add_parser("predict", help="Run inference on a JSON input file.")
    predict_parser.add_argument("--input", required=True)
    predict_parser.add_argument("--output", default=None)
    predict_parser.add_argument("--artifacts-dir", default=None)

    return parser


def run_train(project_root: Path, args: argparse.Namespace) -> None:
    config = load_config(project_root=project_root, config_path=args.config, data_root=args.data_root, artifacts_dir=args.artifacts_dir)
    artifact_dir = ensure_directory(Path(config["artifacts_dir"]))
    set_global_seed(int(config["runtime"]["random_state"]))

    loader = UnifiedDatasetLoader(config)
    dataset = loader.load_all()

    trainer = ModelTrainer(config)
    result = trainer.train(dataset=dataset, artifact_dir=artifact_dir)
    save_training_artifacts(
        artifact_dir=artifact_dir,
        model=result.model,
        feature_builder=result.feature_builder,
        feature_list=result.feature_list,
        schema_metadata=result.schema_metadata,
        training_summary=result.training_summary,
        test_dataset=result.test_dataset,
    )

    print(dumps_json({"selected_model": result.model_name, "evaluation": result.evaluation, "training_summary": result.training_summary}))


def run_evaluate(project_root: Path, args: argparse.Namespace) -> None:
    config = load_config(project_root=project_root, config_path=args.config, data_root=args.data_root, artifacts_dir=args.artifacts_dir)
    artifact_dir = Path(config["artifacts_dir"])
    required_files = [
        artifact_dir / "model.pkl",
        artifact_dir / "feature_builder.pkl",
        artifact_dir / "feature_list.json",
        artifact_dir / "test_dataset.parquet",
    ]
    missing_files = [str(path) for path in required_files if not path.exists()]
    if missing_files:
        raise SystemExit(
            "Missing training artifacts. Run 'python main.py train' first.\nMissing files:\n- "
            + "\n- ".join(missing_files)
        )
    artifacts = load_runtime_artifacts(artifact_dir)
    test_dataset = pd.read_parquet(artifact_dir / "test_dataset.parquet")
    features = artifacts["feature_builder"].transform(test_dataset)[artifacts["feature_list"]]
    from src.evaluation.metrics import evaluate_model

    evaluation = evaluate_model(
        model=artifacts["model"],
        features=features,
        labels=test_dataset["label"],
        feature_names=artifacts["feature_list"],
        output_dir=artifact_dir,
    )
    print(dumps_json(evaluation))


def run_predict(project_root: Path, args: argparse.Namespace) -> None:
    artifact_dir = Path(args.artifacts_dir) if args.artifacts_dir is not None else project_root / "artifacts"
    required_files = [
        artifact_dir / "model.pkl",
        artifact_dir / "feature_builder.pkl",
        artifact_dir / "feature_list.json",
    ]
    missing_files = [str(path) for path in required_files if not path.exists()]
    if missing_files:
        raise SystemExit(
            "Missing training artifacts. Run 'python main.py train' first.\nMissing files:\n- "
            + "\n- ".join(missing_files)
        )
    predictor = CybersecurityPredictor(artifact_dir=artifact_dir)
    results = predictor.predict_file(
        input_path=Path(args.input),
        output_path=Path(args.output) if args.output is not None else None,
    )
    print(dumps_json(results))


def main() -> None:
    project_root = Path(__file__).resolve().parent
    setup_logging()
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.command == "train":
        run_train(project_root, args)
    elif args.command == "evaluate":
        run_evaluate(project_root, args)
    elif args.command == "predict":
        run_predict(project_root, args)
    else:  # pragma: no cover - argparse guarantees command
        raise ValueError(f"Unsupported command: {args.command}")


if __name__ == "__main__":
    main()

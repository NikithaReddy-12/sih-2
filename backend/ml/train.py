"""Train a forecast model.

A NetFlow-V3 CSV (FLOW_START_MILLISECONDS in the header) runs the v3 pipeline.
A directory of CICFlowMeter captures runs the earlier CIC logistic model and LSTM.
The synthetic baseline.joblib is not touched.

    python -m ml.train --csv PATH --window-s 60 --seeds 5
"""
import argparse
from pathlib import Path

from .cicids import WINDOW_S, _print_report as print_logistic, resolve_data_dir, run_experiment
from .netflow_v3 import is_netflow_v3
from .world_model_impl import _print_report as print_world, train_and_evaluate


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Train PREDICT-X forecast models.")
    parser.add_argument(
        "--csv",
        default=None,
        help="NetFlow-V3 CSV, or a directory of CICFlowMeter captures. Required unless PREDICT_X_DATA_DIR is set.",
    )
    parser.add_argument(
        "--data-dir",
        default=None,
        help="Alias for --csv when the captures are a directory.",
    )
    parser.add_argument(
        "--window-s",
        type=int,
        default=WINDOW_S,
        help="Window length in seconds (for example 10, 30, or 60).",
    )
    parser.add_argument("--seeds", type=int, default=5, help="Number of seeds, starting at 0. Used by the NetFlow-V3 pipeline.")
    parser.add_argument("--min-attack-frac", type=float, default=0.05, help="Attack-flow share that sets a window stage. DoS/DDoS/Web windows above this share are dropped.")
    args = parser.parse_args(argv)
    if args.window_s < 1:
        parser.error("--window-s must be at least 1")
    if args.seeds < 1:
        parser.error("--seeds must be at least 1")
    if not 0 < args.min_attack_frac < 1:
        parser.error("--min-attack-frac must be between 0 and 1")
    chosen = args.csv or args.data_dir
    if chosen and is_netflow_v3(Path(chosen)):
        from .model_v3 import train_v3
        train_v3(Path(chosen), window_s=args.window_s, seeds=args.seeds, min_attack_frac=args.min_attack_frac)
        return
    try:
        data_dir = resolve_data_dir(chosen)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    logistic = run_experiment(data_dir, window_s=args.window_s)
    print_logistic(logistic)
    world = train_and_evaluate(data_dir, window_s=args.window_s)
    print("rollout_ok", world["rollout_check"])
    print_world(world)


if __name__ == "__main__":
    main()

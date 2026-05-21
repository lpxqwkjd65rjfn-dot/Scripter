from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(prog="rkn-probe")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    parser.add_argument("--check", action="store_true", help="Validate config and exit")
    parser.add_argument("--mock", action="store_true", help="Use mock providers (no real API calls)")
    args = parser.parse_args()

    from .config import load_config

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"[error] Config not found: {cfg_path}", file=sys.stderr)
        print("        Copy config.example.yaml -> config.yaml and edit it.", file=sys.stderr)
        return 2

    try:
        config = load_config(cfg_path)
    except Exception as exc:
        print(f"[error] Invalid config: {exc}", file=sys.stderr)
        return 2

    if args.check:
        enabled = [name for name, p in config.providers.items() if p.enabled]
        print(f"[ok] Config valid. Enabled providers: {enabled or '(none)'}")
        return 0

    from .app import RknProbeApp

    app = RknProbeApp(config=config, mock=args.mock)
    app.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

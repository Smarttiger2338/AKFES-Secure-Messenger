from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import shutil
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SKETCH_NAME = "AKFES_Device_Authenticator"
PLACEHOLDER = "AKFES_DEVICE_SECRET_HEX_PLACEHOLDER"
DEFAULT_OUTPUT_ROOT = (
    Path(os.environ["LOCALAPPDATA"]) / "AKFES" / "arduino"
    if os.environ.get("LOCALAPPDATA")
    else ROOT / "generated"
)


def read_env_value(path: Path, name: str) -> str:
    matches: list[str] = []
    for raw_line in path.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == name:
            matches.append(value.strip())
    if len(matches) != 1:
        raise SystemExit(f"{path}: expected exactly one {name} entry")
    return matches[0]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a device-bound AKFES Arduino sketch without exposing the server master secret."
    )
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    supplied_device_id = args.device_id.strip()
    try:
        canonical_device_id = str(uuid.UUID(supplied_device_id))
    except ValueError as exc:
        raise SystemExit("device ID must be the 36-character UUID shown by the AKFES client") from exc
    if supplied_device_id.lower() != canonical_device_id:
        raise SystemExit("device ID must use the canonical UUID form shown by the AKFES client")

    master = (
        read_env_value(args.env_file.resolve(), "ARDUINO_MASTER_SECRET")
        if args.env_file
        else os.environ.get("ARDUINO_MASTER_SECRET", "")
    )
    if len(master) < 32:
        raise SystemExit("ARDUINO_MASTER_SECRET is missing or shorter than 32 characters")

    source_dir = ROOT / SKETCH_NAME
    source_ino = source_dir / f"{SKETCH_NAME}.ino"
    source_header = source_dir / "akfes_sha256.h"
    sketch_dir = args.output_root.resolve() / canonical_device_id / SKETCH_NAME
    if sketch_dir.exists() and not args.force:
        raise SystemExit(f"output already exists: {sketch_dir} (use --force to replace its files)")
    sketch_dir.mkdir(parents=True, exist_ok=True)

    source_text = source_ino.read_text(encoding="utf-8")
    if source_text.count(PLACEHOLDER) != 1:
        raise SystemExit("firmware template placeholder is missing or duplicated")
    device_secret = hmac.new(
        master.encode("utf-8"),
        ("akfes-arduino-device-v1:" + canonical_device_id).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    provisioned_text = source_text.replace(PLACEHOLDER, device_secret)
    (sketch_dir / source_ino.name).write_text(provisioned_text, encoding="utf-8", newline="\n")
    shutil.copyfile(source_header, sketch_dir / source_header.name)

    print(f"Provisioned sketch: {sketch_dir / source_ino.name}")
    print(f"Device ID: {canonical_device_id}")
    print("The device key was written to the generated sketch and was not printed.")


if __name__ == "__main__":
    main()

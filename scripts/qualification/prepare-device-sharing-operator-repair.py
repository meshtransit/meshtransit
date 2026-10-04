"""Prepare canonical operator metadata repair, guarded by the deployment gate.

This tool emits SQL only. It does not connect to a database or modify source.
"""
import argparse
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    "000051_resource_sharing_function_ownership.sql",
    "000052_policy_imported_resource_function_ownership.sql",
    "000053_resource_sharing_access_name_function_ownership.sql",
    "000054_resource_sharing_private_endpoint_function_ownership.sql",
    "000055_resource_sharing_private_endpoint_publication_ownership.sql",
    "000079_direct_device_endpoint_function_ownership.sql",
    "000088_imported_policy_simulation_reader_ownership.sql",
)

def without_boundaries(source, boundaries):
    return "\n".join(line for line in source.splitlines() if line.strip() not in boundaries)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    parts = ["BEGIN;", "SET LOCAL lock_timeout='5s';", "SET LOCAL statement_timeout='15s';"]
    for name in SOURCES:
        source = (ROOT / "migrations" / "operator" / name).read_text(encoding="utf-8")
        parts.extend(("-- Canonical operator source: " + name,
                      without_boundaries(source, {"BEGIN;", "COMMIT;"})))
    gate = (ROOT / "scripts" / "qualification" / "check-device-sharing-database.sql").read_text(encoding="utf-8")
    parts.extend((without_boundaries(gate, {"BEGIN READ ONLY;", "ROLLBACK;"}), "COMMIT;"))
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write("\n\n".join(parts) + "\n")

if __name__ == "__main__":
    main()

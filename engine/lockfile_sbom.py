
"""Generate a CycloneDX SBOM from a strictly pinned pip-compile lockfile."""

import argparse
import json
import re
import uuid
from pathlib import Path


PACKAGE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]*)=="
    r"([A-Za-z0-9][A-Za-z0-9.!+_-]*)$"
)

HASH_RE = re.compile(r"^--hash=sha256:[0-9a-fA-F]{64}$")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lockfile(path: Path) -> list[dict]:
    if not path.is_file():
        raise ValueError(f"Missing lockfile: {path}")

    packages = []
    seen = set()
    current = None
    hashes = []

    def finish():
        nonlocal current, hashes

        if current is None:
            return

        if not hashes:
            raise ValueError(
                f"Missing SHA-256 hashes for {current['name']}"
            )

        current["hashes"] = sorted(set(hashes))
        packages.append(current)
        current = None
        hashes = []

    for line_number, raw in enumerate(
        path.read_text(encoding="utf-8").splitlines(), 1
    ):
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        continuation = line.endswith("\\")
        if continuation:
            line = line[:-1].strip()

        match = PACKAGE_RE.fullmatch(line)

        if match:
            if current is not None:
                raise ValueError(
                    f"Unterminated package block before line {line_number}"
                )

            if not continuation:
                raise ValueError(
                    f"Missing hash continuation at line {line_number}"
                )

            name, version = match.groups()
            normalized = normalize_name(name)

            if normalized in seen:
                raise ValueError(f"Duplicate package: {name}")

            seen.add(normalized)

            current = {
                "name": normalized,
                "version": version,
            }
            continue

        if HASH_RE.fullmatch(line):
            if current is None:
                raise ValueError(
                    f"Orphan hash at line {line_number}"
                )

            hashes.append(line.split(":", 1)[1].lower())

            if not continuation:
                finish()

            continue

        raise ValueError(
            f"Unsupported lockfile syntax at line {line_number}: "
            f"{line}"
        )
    if current is not None:
        raise ValueError(
            f"Unterminated package block: {current['name']}"
        )

    finish()

    if not packages:
        raise ValueError("Lockfile contains no packages")

    return sorted(packages, key=lambda p: p["name"])


def generate_sbom(packages: list[dict]) -> dict:
    components = []

    for package in packages:
        name = package["name"]
        version = package["version"]

        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
            "bom-ref": f"pkg:pypi/{name}@{version}",
            "hashes": [
                {
                    "alg": "SHA-256",
                    "content": digest,
                }
                for digest in package["hashes"]
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "pipelineguard-demo-app",
            }
        },
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--lockfile", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    packages = parse_lockfile(Path(args.lockfile))
    sbom = generate_sbom(packages)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(sbom, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"SBOM generated: {output} "
        f"({len(packages)} locked packages)"
    )


if __name__ == "__main__":
    main()

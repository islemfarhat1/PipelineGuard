
import pytest

from engine.lockfile_sbom import (
    generate_sbom,
    parse_lockfile,
)


VALID_HASH = "a" * 64


def write_lock(tmp_path, content):
    path = tmp_path / "requirements.lock"
    path.write_text(content, encoding="utf-8")
    return path


def test_valid_lockfile(tmp_path):
    path = write_lock(
        tmp_path,
        f"fastapi==0.162.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n"
    )

    packages = parse_lockfile(path)

    assert len(packages) == 1
    assert packages[0]["name"] == "fastapi"
    assert packages[0]["version"] == "0.162.0"

    sbom = generate_sbom(packages)

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == 1


@pytest.mark.parametrize(
    "content",
    [
        "fastapi==0.162.0\n",
        "fastapi>=0.162.0\n",
        f"fastapi==0.162.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n"
        f"fastapi==0.162.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n",
        "fastapi==0.162.0 \\\n"
        "    --hash=sha256:invalid\n",
        "",
    ],
)
def test_invalid_lockfiles_are_rejected(tmp_path, content):
    path = write_lock(tmp_path, content)

    with pytest.raises(ValueError):
        parse_lockfile(path)


def test_normalized_duplicate_is_rejected(tmp_path):
    path = write_lock(
        tmp_path,
        f"typing_extensions==4.16.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n"
        f"typing-extensions==4.16.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n"
    )

    with pytest.raises(ValueError, match="Duplicate"):
        parse_lockfile(path)
def test_trailing_continuation_is_rejected(tmp_path):
    path = write_lock(
        tmp_path,
        f"fastapi==0.162.0 \\\n"
        f"    --hash=sha256:{VALID_HASH} \\\n"
    )

    with pytest.raises(ValueError, match="Unterminated"):
        parse_lockfile(path)


def test_new_package_before_previous_block_ends_is_rejected(tmp_path):
    path = write_lock(
        tmp_path,
        f"fastapi==0.162.0 \\\n"
        f"    --hash=sha256:{VALID_HASH} \\\n"
        f"uvicorn==0.54.0 \\\n"
        f"    --hash=sha256:{VALID_HASH}\n"
    )

    with pytest.raises(ValueError, match="Unterminated"):
        parse_lockfile(path)
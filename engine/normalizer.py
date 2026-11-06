from engine.models import Scanner, SecurityFinding, Severity

def normalize_trivy(report: dict) -> list[SecurityFinding]:
    if not isinstance(report, dict):
        raise ValueError("Invalid Trivy report: expected JSON object")
    if not isinstance(report.get("Results"), list):
        raise ValueError("Invalid Trivy report: missing Results list")
    findings = []
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise ValueError(
                "Invalid Trivy report: result must be an object"
            )

        ecosystem = result.get("Type", "unknown")

        vulnerabilities = result.get("Vulnerabilities", [])

        if not isinstance(vulnerabilities, list):
            raise ValueError(
                "Invalid Trivy report: Vulnerabilities must be a list"
            )

        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(
                    "Invalid Trivy report: vulnerability must be an object"
                )

            severity_value = vulnerability.get("Severity", "INFO")

            finding = SecurityFinding(
                scanner=Scanner.TRIVY,
                severity=Severity(severity_value),
                title=vulnerability.get("Title") or "Unknown vulnerability",
                identifier=vulnerability.get("VulnerabilityID", "UNKNOWN"),
                location=(
    f"{ecosystem}:"
    f"{vulnerability.get('PkgName', 'unknown')}"
),
                description=vulnerability.get("Description") or ""
            )

            findings.append(finding)
    return findings

def normalize_semgrep(report: dict) -> list[SecurityFinding]:

    if not isinstance(report, dict):
        raise ValueError(
            "Invalid Semgrep report: expected JSON object"
        )

    if not isinstance(report.get("results"), list):
        raise ValueError(
            "Invalid Semgrep report: missing results list"
        )
    findings = []

    severity_mapping = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
    }


    for result in report["results"]:
        if not isinstance(result, dict):
            raise ValueError(
                "Invalid Semgrep report: result must be an object"
            )

        extra = result.get("extra")

        if not isinstance(extra, dict):
            raise ValueError(
                "Invalid Semgrep report: extra must be an object"
            )

        severity_value = extra.get("severity")

        if severity_value not in severity_mapping:
            raise ValueError(
                f"Invalid Semgrep severity: {severity_value}"
            )


        finding = SecurityFinding(
            scanner=Scanner.SEMGREP,
            severity=severity_mapping[severity_value],
            title=extra.get("message", "Unknown finding"),
            identifier=result.get("check_id", "UNKNOWN"),
            location=(
                f"{result.get('path', 'unknown')}:"
                f"{result.get('start', {}).get('line', 0)}"
            ),
            description=extra.get("message", "")
        )

        findings.append(finding)

    return findings


def normalize_gitleaks(report: list[dict]) -> list[SecurityFinding]:
    if not isinstance(report, list):
        raise ValueError(
            "Invalid Gitleaks report: expected JSON array"
        )

    findings = []

    for secret in report:

        # 1. Validate finding structure
        if not isinstance(secret, dict):
            raise ValueError(
                "Invalid Gitleaks report: finding must be an object"
            )

        # 2. Validate required string fields
        for field in ("RuleID", "File"):
            if (
                not isinstance(secret.get(field), str)
                or not secret[field].strip()
            ):
                raise ValueError(
                    f"Invalid Gitleaks finding: missing or invalid {field}"
                )

        # 3. Validate line number
        if (
            type(secret.get("StartLine")) is not int
            or secret["StartLine"] < 1
        ):
            raise ValueError(
                "Invalid Gitleaks finding: invalid StartLine"
            )

        # 4. Create normalized security finding
        finding = SecurityFinding(
            scanner=Scanner.GITLEAKS,
            severity=Severity.CRITICAL,
            title=secret.get(
                "Description", "Potential exposed secret"
            ),
            identifier=secret["RuleID"],
            location=f"{secret['File']}:{secret['StartLine']}",
            description="Potential secret detected by Gitleaks"
        )

        # 5. Add finding to the list
        findings.append(finding)

    return findings

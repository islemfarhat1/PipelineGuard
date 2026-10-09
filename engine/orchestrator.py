
from engine.loader import load_scan_report
from engine.models import Scanner
from engine.policy import PolicyResult, evaluate_scans
from engine.scan_validation import validate_gitleaks_exit_code


def run_pipelineguard(
    trivy_path: str,
    semgrep_path: str,
    gitleaks_path: str,
    gitleaks_exit_code: int
) -> PolicyResult:

    trivy_scan = load_scan_report(Scanner.TRIVY, trivy_path)

    semgrep_scan = load_scan_report(Scanner.SEMGREP, semgrep_path)

    gitleaks_scan = load_scan_report(Scanner.GITLEAKS, gitleaks_path)

    gitleaks_scan = validate_gitleaks_exit_code(
        gitleaks_scan,
        gitleaks_exit_code
    )

    scans = [
        trivy_scan,
        semgrep_scan,
        gitleaks_scan
    ]

    return evaluate_scans(scans)

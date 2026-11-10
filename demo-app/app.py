from fastapi import FastAPI

app = FastAPI(
    title="PipelineGuard Demo App",
    version="1.0.0"
)

@app.get("/")
def root():
    return {
        "message": "PipelineGuard demo application",
        "status": "running"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# T3 shift: these three comment lines move the existing fixture down.
# The eval() line itself is not modified, so its finding must stay
# EXISTING (not NEW) and the pull request must PASS.
# VALIDATION FIXTURE (T3) - to be removed after validation.
# Constant input only: no user data can reach eval(), so this is not
# exploitable. It exists so main contains one pre-existing Semgrep finding.
def _t3_validation_fixture():
    return eval("1 + 1")

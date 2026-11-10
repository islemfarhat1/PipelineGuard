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

# VALIDATION TEST T4 - DO NOT MERGE.
# Deliberately vulnerable: user input reaches eval() (code injection).
# Checks that the digest-pinned, offline Semgrep container still finds it.
@app.get("/calc")
def calc(expr: str):
    return {"result": eval(expr)}
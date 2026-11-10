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

# VALIDATION TEST T1 - DO NOT MERGE.
# Deliberately vulnerable: user input reaches eval() (code injection).
@app.get("/calc")
def calc(expr: str):
    return {"result": eval(expr)}
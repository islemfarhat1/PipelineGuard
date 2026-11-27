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
@app.get("/demo-calculation")
def demo_calculation():
    return {"result": eval("1 + 1")}

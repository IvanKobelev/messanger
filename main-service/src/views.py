from fastapi import FastAPI


app = FastAPI()


@app.get("/health-check")
def health_check():
    """Health check main-service."""
    return "Hello, world!"
import uvicorn
import os
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from factory import RemediationFactory

from dotenv import load_dotenv
load_dotenv() # Load variables before initializing Factory

app = FastAPI(title="Sentinel Ephemeral Remediation Service")
factory = RemediationFactory()

class RemediationRequest(BaseModel):
    repo_url: str
    target_tag: str

def execute_worker(repo_url: str, target_tag: str):
    """Worker to handle the full remediation lifecycle."""
    try:
        # factory.build_sandbox() # Optional: ensure latest image on each run
        factory.execute_ephemeral_fix(repo_url, target_tag)
    except Exception as e:
        print(f"🚨 Factory Execution Failed: {e}")

@app.post("/remediate")
async def trigger_remediation(request: RemediationRequest, background_tasks: BackgroundTasks):
    """
    Triggers the autonomous remediation factory.
    Integration point for CI/CD via JWT/API Key Auth.
    """
    if not request.repo_url.startswith("https://github.com"):
        raise HTTPException(status_code=400, detail="Invalid GitHub URL")
    
    background_tasks.add_task(execute_worker, request.repo_url, request.target_tag)
    
    return {
        "status": "accepted",
        "message": f"Remediation started for {request.repo_url} at {request.target_tag}"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
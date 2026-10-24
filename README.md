# Store Manager Licensing API (stage 1)

This separate FastAPI service currently provides only a health check. License generation, customer activation, and persistence are not implemented.

## Run locally

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

In another PowerShell window, check the endpoint:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Render

`render.yaml` configures a small Python web service, installs `requirements.txt`, starts Uvicorn on Render's `$PORT`, and uses `/health` for health checks. Connect this folder as the root of its own Git repository and create a Render Blueprint from `render.yaml`.

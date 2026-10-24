# Store Manager Licensing Backend

This repository contains the online licensing API for Store Manager in `licensing-server/`. The licensing backend is prepared as a deployment candidate; check the existing Render service's deployed commit before treating these endpoints as live.

The Store Manager desktop application, its database, routes, and installer are separate and have not been changed by this backend work.

## Deployment

The repository-root `render.yaml` describes one existing Free Python web service, with the service root at `licensing-server/`. It does not create a database resource. License records use the external Neon PostgreSQL database configured through Render environment variables.

- Build command: `pip install -r requirements.txt`
- Start command: `alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port $PORT`
- Health check: `/health`

The service expects database URLs, the admin token, and the Ed25519 private signing key in Render's Environment settings. Keep those values out of GitHub. The startup command applies Alembic migrations before starting FastAPI.

See [licensing-server/README.md](licensing-server/README.md) for setup, environment variables, routes, tests, and the rollback plan.

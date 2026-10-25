# RAYZO Token + Admin ID panel

The webpage shows only Bot Token, Admin ID(s), Start/Stop, status and logs. It hides backend URL and panel password inputs from users.

## Important limitation
A static Netlify page cannot itself run a Python Telegram bot. You must deploy `control_server.py`, `app.py`, and `requirements.txt` to a separate always-on Python backend. Before publishing, replace `BACKEND_URL` and `PANEL_PASSWORD` placeholders in `index.html`. This shared password is visible in public HTML source, so use this only for a private/trusted panel. For a public panel, implement real login or a server-side proxy instead.

## Backend environment variables (set in hosting dashboard, no .env file needed)
- `PANEL_PASSWORD`: long unique panel password matching the value in index.html
- `PANEL_ENCRYPTION_KEY`: Fernet key for encrypted bot credentials at rest
- `FRONTEND_ORIGIN`: exact Netlify origin, e.g. `https://your-site.netlify.app`
- `PORT`: normally supplied by host
- Optional `PANEL_DATA_DIR`: persistent storage path

Generate key with: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

Backend start command: `gunicorn --workers 1 --threads 8 --bind 0.0.0.0:$PORT control_server:app`

Do not deploy the backend as serverless functions. Use persistent storage if config/logs must survive restarts. Process mode does not isolate uploaded code; this is not safe for public multi-user arbitrary-code hosting. Python syntax checked locally; not live tested with Telegram.

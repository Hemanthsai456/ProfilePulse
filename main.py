"""ProfilePulse entrypoint.

Run directly via:
    python main.py
or via uvicorn:
    uvicorn main:app --reload
    uvicorn app.main:app --reload
"""

from app.main import app, __version__

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)

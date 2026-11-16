"""Punto de entrada: arranca el servidor con uvicorn."""

import os

import uvicorn


def run() -> None:
    uvicorn.run(
        "dnsinspector.api:create_app",
        factory=True,
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "8000")),
    )


if __name__ == "__main__":
    run()

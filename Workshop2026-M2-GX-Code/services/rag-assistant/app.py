"""API de l'assistant opérateur. Lecture seule : aucune route n'agit sur la plateforme."""
import logging
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from rag import build_from_env

logging.basicConfig(level=logging.INFO)
app = FastAPI(title="assistant-operateur", docs_url=None, redoc_url=None)
assistant = None


class Question(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


@app.on_event("startup")
def startup():
    global assistant
    assistant = build_from_env()


@app.post("/ask")
def ask(q: Question):
    try:
        a = assistant.ask(q.question)
    except Exception as exc:                      # Ollama arrêté, modèle absent...
        logging.getLogger("rag").warning("génération impossible: %s", type(exc).__name__)
        raise HTTPException(503, "Le modèle local est indisponible. Consultez docs/runbooks.md.")
    return {"answer": a.text, "sources": a.sources, "scores": a.scores}


@app.post("/reindex")
def reindex():
    return {"chunks": assistant.reindex()}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "chunks": assistant.n_chunks if assistant else 0}

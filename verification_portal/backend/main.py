"""HTTP API for the Stage 8 verification portal."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from key_registry import KeyRegistry

from .evidence_store import ActionEvidenceStore
from .verify_pipeline import VerificationPipeline


class VerifyByActionId(BaseModel):
    action_id: str


def create_app(
    key_registry: KeyRegistry | None = None, evidence_store: ActionEvidenceStore | None = None
) -> FastAPI:
    """Create the portal with injectable evidence for real integrations/tests."""
    app = FastAPI(title="AoR Verification Portal", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5174", "http://localhost:5174"],
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )
    app.state.key_registry = key_registry or KeyRegistry()
    app.state.evidence_store = evidence_store or ActionEvidenceStore()

    @app.post("/verify")
    async def verify(request: Request):
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("multipart/form-data"):
            form = await request.form()
            uploaded = form.get("file")
            if uploaded is None or not hasattr(uploaded, "read"):
                raise HTTPException(status_code=422, detail="provide an .eml file")
            return VerificationPipeline(request.app.state.key_registry, request.app.state.evidence_store).run_verification(await uploaded.read(), None)
        try:
            body = VerifyByActionId.model_validate(await request.json())
        except Exception as exc:
            raise HTTPException(status_code=422, detail="provide JSON {action_id: ...} or an .eml upload") from exc
        return VerificationPipeline(request.app.state.key_registry, request.app.state.evidence_store).run_verification(None, body.action_id)

    @app.get("/verify/{action_id}")
    async def verify_by_action_id(action_id: str, request: Request):
        return VerificationPipeline(request.app.state.key_registry, request.app.state.evidence_store).run_verification(None, action_id)

    return app


app = create_app()

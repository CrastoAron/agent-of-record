"""HTTP boundary for the Stage 4 AoR signature verifier."""

from __future__ import annotations

import base64
import binascii
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware

from action_executor.smtp_action import SMTPConfig
from aor.agents.audit import AuditAgent
from aor.agents.base import AgentRegistry
from aor.agents.database import DatabaseAgent
from aor.agents.email import EmailAgent, EmailAction
from aor.agents.file import FileAgent
from aor.agents.router import AgentRouter
from key_registry import KeyRegistry
from key_registry.jwks import import_jwk
from key_registry.models import RegisterKeyRequest, RevokeKeyRequest
from key_registry.storage import SQLiteKeyStorage

from ledger_core import Ledger
from poi_generator import build_poi, sign_poi
from poi_generator.agent_keys import load_agent_keypair, register_agent_public_key
from verification_portal.backend.evidence_store import ActionEvidence, ActionEvidenceStore
from verification_portal.backend.verify_pipeline import VerificationPipeline
from tsa_anchor.anchor_scheduler import AnchorStore, anchor_current_root

from .models import PubkeyRegistration, SignedEnvelope
from .database import SQLiteDatabase
from .agent_runtime import AgentRuntime, AgentRuntimeError
from .nonce_store import NonceStore
from .pubkey_store import PubkeyStore
from .verifier import SignatureVerifier

logger = logging.getLogger(__name__)


def _registration_key_bytes(registration: PubkeyRegistration) -> bytes:
    if registration.public_key_jwk is not None:
        return import_jwk(registration.public_key_jwk)
    try:
        return base64.b64decode(registration.public_key_b64 or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("public_key_b64 must be valid base64 DER") from exc


def _registry_registration_key_bytes(registration: RegisterKeyRequest) -> bytes:
    if registration.public_key_jwk is not None:
        return import_jwk(registration.public_key_jwk)
    try:
        return base64.b64decode(registration.public_key_b64 or "", validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("public_key_b64 must be valid base64 key material") from exc


def _default_verified_handler(_: SignedEnvelope) -> dict[str, str]:
    """Placeholder boundary: no LLM/tool call exists in Stage 4."""
    return {"next": "would proceed to PoI Generator in Stage 6"}


def _operation_entry(operation: str, status: str, detail: str, *, pubkey_id: str | None = None) -> dict[str, str]:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "operation": operation,
        "status": status,
        "detail": detail,
        **({"pubkey_id": pubkey_id} if pubkey_id else {}),
    }


def _bearer_token(request: Request) -> str | None:
    value = request.headers.get("authorization", "")
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" and token.strip() else None


def _request_user(request: Request, *, required: bool = False) -> dict[str, str] | None:
    user = request.app.state.database.user_from_token(_bearer_token(request))
    if required and user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication_required")
    return user


def create_app(
    pubkey_store: PubkeyStore | KeyRegistry | None = None,
    nonce_store: NonceStore | None = None,
    on_verified: Callable[[SignedEnvelope], dict[str, str]] | None = None,
    key_registry: KeyRegistry | None = None,
    database_path: str | Path | None = None,
    agent_runtime: AgentRuntime | None = None,
    workspace_dir: str | Path | None = None,
) -> FastAPI:
    """Build an app with injectable stores/handler for isolated tests."""
    service = FastAPI(title="AoR Signature Verifier", version="0.1.0")
    service.add_middleware(
        CORSMiddleware,
        allow_origins=["http://127.0.0.1:5173", "http://localhost:5173", "http://127.0.0.1:4173", "http://localhost:4173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    database_location = str(database_path) if database_path is not None else ":memory:"
    service.state.database = SQLiteDatabase(database_location)
    # The default is now the Stage 5 registry. A legacy PubkeyStore remains
    # injectable for focused Stage 4 tests through the same get_pubkey API.
    service.state.pubkey_store = key_registry or pubkey_store or KeyRegistry(SQLiteKeyStorage(database_location))
    service.state.key_registry = (
        service.state.pubkey_store if isinstance(service.state.pubkey_store, KeyRegistry) else None
    )
    service.state.nonce_store = nonce_store or NonceStore()
    service.state.verifier = SignatureVerifier(service.state.pubkey_store, service.state.nonce_store)
    service.state.on_verified = on_verified or _default_verified_handler
    service.state.operations: list[dict[str, str]] = []
    service.state.ledger = Ledger()
    service.state.verified_envelopes: list[dict[str, str]] = []
    service.state.artifact_store = ActionEvidenceStore(service.state.database)
    service.state.anchor_store = AnchorStore()
    service.state.outbox_dir = Path(__file__).resolve().parents[1] / ".aor_outbox"
    service.state.email_agent = EmailAgent(
        SMTPConfig(dry_run=True, output_dir=service.state.outbox_dir)
    )
    service.state.workspace_dir = (
        Path(workspace_dir)
        if workspace_dir is not None
        else Path(__file__).resolve().parents[1] / ".aor_workspace"
    )
    service.state.file_agent = FileAgent(service.state.workspace_dir)
    service.state.audit_pipeline = VerificationPipeline(
        service.state.key_registry or service.state.pubkey_store,
        service.state.artifact_store,
        service.state.anchor_store,
    )
    service.state.audit_agent = AuditAgent(
        service.state.audit_pipeline,
        service.state.artifact_store,
    )
    registered_databases = {}
    if database_location != ":memory:" and Path(database_location).is_file():
        registered_databases["aor"] = database_location
    database_workspace = service.state.workspace_dir / "databases"
    if database_workspace.is_dir():
        registered_databases.update({path.stem: path for path in database_workspace.glob("*.sqlite3")})
    service.state.database_agent = DatabaseAgent(
        registered_databases,
        workspace_dir=database_workspace,
    )
    service.state.agent_registry = AgentRegistry([
        service.state.email_agent,
        service.state.file_agent,
        service.state.audit_agent,
        service.state.database_agent,
    ])
    service.state.agent_router = AgentRouter(service.state.agent_registry)
    service.state.agent_runtime = agent_runtime or AgentRuntime(service.state.email_agent)
    service.state.agent_keypair = load_agent_keypair("email-agent")

    @service.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
    async def auth_signup(payload: dict[str, str], request: Request) -> dict[str, object]:
        try:
            user = request.app.state.database.create_user(
                payload.get("name", ""), payload.get("email", ""), payload.get("password", "")
            )
            token = request.app.state.database.create_session(user["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        return {"user": user, "token": token}

    @service.post("/api/auth/login")
    async def auth_login(payload: dict[str, str], request: Request) -> dict[str, object]:
        user = request.app.state.database.authenticate(payload.get("email", ""), payload.get("password", ""))
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password.")
        return {"user": user, "token": request.app.state.database.create_session(user["id"])}

    @service.get("/api/auth/me")
    async def auth_me(request: Request) -> dict[str, object]:
        user = _request_user(request, required=True)
        return {"user": user}

    @service.post("/api/auth/logout")
    async def auth_logout(request: Request) -> dict[str, str]:
        request.app.state.database.revoke_session(_bearer_token(request))
        return {"status": "signed_out"}

    @service.post("/api/auth/reset-password")
    async def auth_reset_password(payload: dict[str, str], request: Request) -> dict[str, str]:
        # A real email delivery provider is intentionally outside this stage.
        # Always return the same response to avoid account enumeration.
        return {"status": "accepted"}

    @service.get("/api/prompts")
    async def list_prompt_records(request: Request) -> dict[str, object]:
        user = _request_user(request, required=True)
        return {"prompts": request.app.state.database.list_prompts(user["id"])}

    @service.post("/register-pubkey", status_code=status.HTTP_201_CREATED)
    async def register_pubkey(registration: PubkeyRegistration, request: Request) -> dict[str, str]:
        try:
            request.app.state.pubkey_store.register_pubkey(
                registration.pubkey_id,
                _registration_key_bytes(registration),
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "register_pubkey",
                "registered",
                f"registered {registration.pubkey_id}",
                pubkey_id=registration.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        return {"status": "registered", "pubkey_id": registration.pubkey_id}

    @service.post("/register-key", status_code=status.HTTP_201_CREATED)
    async def register_key(registration: RegisterKeyRequest, request: Request) -> dict[str, str]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        try:
            record = registry.register_key(
                agent_id=registration.agent_id,
                pubkey_id=registration.pubkey_id,
                public_key_bytes=_registry_registration_key_bytes(registration),
                algorithm=registration.algorithm,
                valid_from=registration.valid_from or datetime.now(timezone.utc),
                valid_until=registration.valid_until,
            )
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "register_key",
                "registered",
                f"registered {record.pubkey_id}",
                pubkey_id=record.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        return {"status": "registered", "agent_id": record.agent_id, "pubkey_id": record.pubkey_id}

    @service.get("/.well-known/jwks.json")
    async def get_jwks(request: Request) -> dict[str, list[dict[str, str]]]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        return registry.export_jwks()

    @service.post("/revoke-key")
    async def revoke_key(revocation: RevokeKeyRequest, request: Request) -> dict[str, str]:
        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured",
            )
        if not registry.revoke_key(revocation.pubkey_id):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="key_not_found")
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "revoke_key",
                "revoked",
                f"revoked {revocation.pubkey_id}",
                pubkey_id=revocation.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        return {"status": "revoked", "pubkey_id": revocation.pubkey_id}

    @service.get("/api/operations")
    async def list_operations(request: Request) -> dict[str, object]:
        return {
            "count": len(request.app.state.operations),
            "operations": list(request.app.state.operations),
        }

    @service.post("/api/anchor")
    async def anchor_ledger(request: Request) -> dict[str, object]:
        record = anchor_current_root(
            request.app.state.ledger,
            store=request.app.state.anchor_store,
        )
        return {
            "status": record.status,
            "ledger_root": record.ledger_root.hex(),
            "gen_time": record.gen_time.isoformat() if record.gen_time else None,
            "anchored_at": record.anchored_at.isoformat(),
            "detail": record.detail,
        }

    @service.get("/api/anchors")
    async def list_anchors(request: Request) -> dict[str, object]:
        records = request.app.state.anchor_store.all_records()
        return {
            "count": len(records),
            "anchors": [
                {
                    "status": record.status,
                    "ledger_root": record.ledger_root.hex(),
                    "gen_time": record.gen_time.isoformat() if record.gen_time else None,
                    "anchored_at": record.anchored_at.isoformat(),
                    "detail": record.detail,
                }
                for record in records
            ],
        }

    @service.post("/verify")
    async def verify_artifact(request: Request):
        content_type = request.headers.get("content-type", "")
        pipeline = VerificationPipeline(
            request.app.state.key_registry or request.app.state.pubkey_store,
            request.app.state.artifact_store,
            request.app.state.anchor_store,
        )
        if content_type.startswith("multipart/form-data"):
            form = await request.form()
            uploaded = form.get("file")
            if uploaded is None or not hasattr(uploaded, "read"):
                raise HTTPException(status_code=422, detail="provide an .eml file")
            trace = pipeline.run_verification(await uploaded.read(), None)
            if trace.action_id:
                request.app.state.database.update_verification(trace.action_id, trace.model_dump(mode="json"))
            return trace
        try:
            body = await request.json()
            action_id = str(body["action_id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail="provide JSON {action_id: ...} or an .eml upload",
            ) from exc
        trace = pipeline.run_verification(None, action_id)
        request.app.state.database.update_verification(action_id, trace.model_dump(mode="json"))
        return trace

    @service.get("/verify/{action_id}")
    async def verify_by_action_id(action_id: str, request: Request):
        pipeline = VerificationPipeline(
            request.app.state.key_registry or request.app.state.pubkey_store,
            request.app.state.artifact_store,
            request.app.state.anchor_store,
        )
        trace = pipeline.run_verification(None, action_id)
        request.app.state.database.update_verification(action_id, trace.model_dump(mode="json"))
        return trace

    @service.post("/api/prompt")
    async def verify_prompt(envelope: SignedEnvelope, request: Request) -> dict[str, str]:
        authenticated_user = _request_user(request)
        if authenticated_user is not None and envelope.user_id != authenticated_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="prompt_user_mismatch")
        result = request.app.state.verifier.verify_envelope(envelope)
        if not result.valid:
            request.app.state.operations.insert(
                0,
                _operation_entry(
                    "verify_prompt",
                    "rejected",
                    result.reason or "verification_failed",
                    pubkey_id=envelope.pubkey_id,
                ),
            )
            request.app.state.operations = request.app.state.operations[:50]
            logger.warning("AoR verification rejected: reason=%s", result.reason)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="verification_failed",
            )
        downstream = request.app.state.on_verified(envelope)
        request.app.state.verified_envelopes.insert(0, envelope.model_dump())
        request.app.state.verified_envelopes = request.app.state.verified_envelopes[:50]
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "verify_prompt",
                "verified",
                f"accepted {envelope.pubkey_id}",
                pubkey_id=envelope.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        return {"status": "verified", **downstream}

    @service.post("/api/generate-artifact")
    async def generate_artifact(envelope: SignedEnvelope, request: Request) -> dict[str, object]:
        authenticated_user = _request_user(request)
        if authenticated_user is not None and envelope.user_id != authenticated_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="prompt_user_mismatch")
        verified_before = any(item == envelope.model_dump() for item in request.app.state.verified_envelopes)
        if not verified_before:
            result = request.app.state.verifier.verify_envelope(envelope)
            if not result.valid:
                request.app.state.operations.insert(
                    0,
                    _operation_entry(
                        "generate_artifact",
                        "rejected",
                        result.reason or "verification_failed",
                        pubkey_id=envelope.pubkey_id,
                    ),
                )
                request.app.state.operations = request.app.state.operations[:50]
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="verification_failed")

        system_prompt = "Only send approved project updates."
        try:
            # The demo planner is intentionally synchronous and deterministic.
            # A queued worker can be introduced with the durable run model if
            # an external provider is added later.
            agent_plan = request.app.state.agent_runtime.plan_action(envelope.prompt)
            agent_action = EmailAction(action_type="email", **agent_plan.payload)
        except AgentRuntimeError as exc:
            request.app.state.operations.insert(
                0,
                _operation_entry("agent_plan", "failed", str(exc), pubkey_id=envelope.pubkey_id),
            )
            request.app.state.operations = request.app.state.operations[:50]
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=str(exc),
            ) from exc

        ledger = request.app.state.ledger
        ledger.append("system_prompt", {"text": system_prompt})
        ledger.append("user_prompt", {"text": envelope.prompt})
        ledger.append("agent_action", agent_action.action_payload())
        action_payload = agent_plan.payload
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "agent_plan",
                "planned",
                f"planned email to {agent_action.to}",
                pubkey_id=envelope.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        agent_private_key, _ = request.app.state.agent_keypair
        register_agent_public_key("email-agent", request.app.state.key_registry or request.app.state.pubkey_store, agent_private_key)
        poi = sign_poi(
            build_poi(
                envelope.prompt,
                system_prompt,
                ledger,
                action_payload,
                "demo-model",
                agent_type=agent_plan.agent_type,
                agent_id=agent_plan.agent_id,
                action_type=agent_plan.action_type,
                policy_decision=agent_plan.policy_decision,
            ),
            agent_private_key,
        )
        output_dir = request.app.state.outbox_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        action_result = request.app.state.email_agent.execute(agent_plan, poi)
        if not action_result.success or not action_result.artifact_ref:
            detail = action_result.details.get("detail") or action_result.details.get("error")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=detail or "artifact_generation_failed")

        artifact_path = max(output_dir.glob("*.eml"), key=lambda path: path.stat().st_mtime)
        request.app.state.artifact_store.register(
            ActionEvidence(
                action_id=action_result.artifact_ref,
                user_envelope=envelope,
                system_prompt=system_prompt,
                ledger=ledger,
                ledger_entry_count_at_action=len(ledger.all_entries()),
                eml_bytes=artifact_path.read_bytes(),
                poi=poi,
                action_type=agent_plan.action_type,
                action_payload=action_payload,
                observed_effect=action_result.observed_effect,
            )
        )
        record_user_id = authenticated_user["id"] if authenticated_user else envelope.user_id
        request.app.state.database.save_prompt(
            envelope,
            user_id=record_user_id,
            action_id=action_result.artifact_ref,
            eml_path=str(artifact_path.resolve()),
        )
        request.app.state.operations.insert(
            0,
            _operation_entry(
                "generate_artifact",
                "artifact_generated",
                f"generated {artifact_path.name}",
                pubkey_id=envelope.pubkey_id,
            ),
        )
        request.app.state.operations = request.app.state.operations[:50]
        return {
            "status": "artifact_generated",
            "agent_mode": request.app.state.agent_runtime.mode,
            "agent_draft": agent_action.model_dump(mode="json"),
            "action_id": action_result.artifact_ref,
            "eml_path": str(artifact_path.resolve()),
            "message_id": action_result.artifact_ref,
        }

    @service.post("/api/agent/execute")
    async def execute_routed_agent(envelope: SignedEnvelope, request: Request) -> dict[str, object]:
        """Route one signed prompt through the registered specialized agents."""
        authenticated_user = _request_user(request)
        if authenticated_user is not None and envelope.user_id != authenticated_user["id"]:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="prompt_user_mismatch")

        verified_before = any(item == envelope.model_dump() for item in request.app.state.verified_envelopes)
        if not verified_before:
            verification = request.app.state.verifier.verify_envelope(envelope)
            if not verification.valid:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="verification_failed")

        route = request.app.state.agent_router.route(envelope.prompt)
        if not route.handled:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"reason": route.reason, "route": route.model_dump(mode="json")},
            )
        try:
            plans = request.app.state.agent_router.plan(envelope.prompt)
        except (KeyError, TypeError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

        registry = request.app.state.key_registry
        if registry is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="key_registry_not_configured_for_agents",
            )

        system_prompt = "Route the signed request to one approved deterministic specialist."
        execution_records: list[dict[str, object]] = []
        previous_result: dict[str, object] | None = None
        last_action_id: str | None = None
        last_eml_path: str | None = None

        for plan in plans:
            if plan.requires_confirmation and not plan.confirmed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail={
                        "reason": "confirmation_required",
                        "plan": plan.model_dump(mode="json"),
                    },
                )

            payload = dict(plan.payload)
            if (
                plan.action_type == "file.create"
                and not payload.get("content")
                and previous_result is not None
            ):
                previous_details = previous_result.get("details")
                if isinstance(previous_details, dict) and previous_details.get("report_markdown"):
                    payload["content"] = previous_details["report_markdown"]
            if (
                plan.agent_type == "audit"
                and plan.action_type in {
                    "audit.verify_action",
                    "audit.explain_failure",
                    "audit.generate_report",
                }
                and not payload.get("action_id")
                and previous_result is not None
                and previous_result.get("artifact_ref")
            ):
                payload["action_id"] = str(previous_result["artifact_ref"])
            if payload != plan.payload:
                plan = plan.model_copy(update={"payload": payload})

            ledger = request.app.state.ledger
            ledger.append("system_prompt", {"text": system_prompt})
            ledger.append("user_prompt", {"text": envelope.prompt})
            ledger.append(
                "agent_action",
                {
                    "agent_type": plan.agent_type,
                    "agent_id": plan.agent_id,
                    "action_type": plan.action_type,
                    "payload": plan.payload,
                },
            )

            agent = request.app.state.agent_registry.get(plan.agent_type)
            agent_private_key, _ = load_agent_keypair(plan.agent_id or f"{plan.agent_type}-agent")
            register_agent_public_key(agent.agent_id, registry, agent_private_key)
            poi = sign_poi(
                build_poi(
                    envelope.prompt,
                    system_prompt,
                    ledger,
                    plan.payload,
                    "deterministic-agent-router",
                    agent_type=plan.agent_type,
                    agent_id=plan.agent_id or agent.agent_id,
                    action_type=plan.action_type,
                    policy_decision=plan.policy_decision,
                ),
                agent_private_key,
            )

            existing_eml = set(request.app.state.outbox_dir.glob("*.eml"))
            action_result = agent.execute(plan, poi)
            if plan.agent_type == "email" and action_result.artifact_ref:
                action_id = action_result.artifact_ref
            else:
                action_id = f"{plan.agent_type}-{uuid4()}"

            artifact_path = None
            if plan.agent_type == "email":
                new_eml = set(request.app.state.outbox_dir.glob("*.eml")) - existing_eml
                if new_eml:
                    artifact_path = max(new_eml, key=lambda path: path.stat().st_mtime)
                    last_eml_path = str(artifact_path.resolve())

            evidence = ActionEvidence(
                action_id=action_id,
                user_envelope=envelope,
                system_prompt=system_prompt,
                ledger=ledger,
                ledger_entry_count_at_action=len(ledger.all_entries()),
                eml_bytes=artifact_path.read_bytes() if artifact_path is not None else None,
                poi=poi,
                action_type=plan.action_type,
                action_payload=plan.payload,
                observed_effect=action_result.observed_effect,
            )
            request.app.state.artifact_store.register(evidence)
            record_user_id = authenticated_user["id"] if authenticated_user else envelope.user_id
            request.app.state.database.save_prompt(
                envelope,
                user_id=record_user_id,
                action_id=action_id,
                eml_path=str(artifact_path.resolve()) if artifact_path is not None else None,
            )
            execution_record = {
                "action_id": action_id,
                "agent_type": plan.agent_type,
                "agent_id": plan.agent_id or agent.agent_id,
                "action_type": plan.action_type,
                "success": action_result.success,
                "details": action_result.details,
                "observed_effect": action_result.observed_effect,
            }
            execution_records.append(execution_record)
            previous_result = action_result.model_dump(mode="json")
            last_action_id = action_id
            request.app.state.operations.insert(
                0,
                _operation_entry(
                    "agent_execute",
                    "completed" if action_result.success else "failed",
                    f"{plan.agent_type}:{plan.action_type}",
                    pubkey_id=envelope.pubkey_id,
                ),
            )
            request.app.state.operations = request.app.state.operations[:50]
            if not action_result.success:
                break

        completed = bool(execution_records) and all(record["success"] for record in execution_records)
        first_plan = plans[0]
        return {
            "status": "agent_action_completed" if completed else "agent_action_failed",
            "agent_mode": "deterministic",
            "route": route.model_dump(mode="json"),
            "agent_draft": {
                "agent_type": first_plan.agent_type,
                "agent_id": first_plan.agent_id,
                "action_type": first_plan.action_type,
                **first_plan.payload,
            },
            "agent_results": execution_records,
            "action_id": last_action_id,
            "eml_path": last_eml_path,
            "message_id": last_action_id,
        }

    return service


app = create_app(database_path=os.getenv("AOR_DATABASE_PATH", str(Path(__file__).resolve().parents[1] / "aor_data.sqlite3")))

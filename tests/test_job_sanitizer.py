"""WebSocket/job payload sanitizasyon testleri."""

import asyncio

from app.core.sanitizer import REDACTED, sanitize_payload
from app.services.job_manager import JobStatus, job_manager


def test_nested_payload_sanitizer_preserves_non_secret_identifiers():
    job_id = "0123456789abcdef0123456789abcdef"
    payload = {
        "job_id": job_id,
        "password": "parola",
        "nested": {
            "api_token": "token-değeri",
            "nt_hash": "a" * 32,
            "safe": "kanıt-açıklaması",
        },
    }
    clean = sanitize_payload(payload)
    assert clean["job_id"] == job_id
    assert clean["password"] == REDACTED
    assert clean["nested"]["api_token"] == REDACTED
    assert clean["nested"]["nt_hash"] == REDACTED
    assert clean["nested"]["safe"] == "kanıt-açıklaması"


def test_job_manager_sanitizes_logs_and_outgoing_results():
    job_id = "sanitize-job"
    secret = "GizliSifre1!"
    state = job_manager.create_job(
        job_id, "10.0.0.5", profile="ad", module="ad_probe",
        meta={"note": f"password={secret}", "safe": "ok"},
    )
    job_manager._job_secrets[job_id] = [secret]
    original_hash = "a" * 32
    state.results = [{"detail": {"nt_hash": original_hash, "safe": "evidence"}}]

    asyncio.run(job_manager.log(
        job_id,
        f"password={secret} token=abc123 "
        "$krb5tgs$23$*alice$CORP.LOCAL$http/dc*$AABBCC",
    ))
    payload = job_manager.serialize(state)
    rendered = str(payload)

    assert secret not in rendered
    assert "abc123" not in rendered
    assert "$krb5tgs" not in rendered
    assert payload["job_id"] == job_id
    assert payload["meta"]["safe"] == "ok"
    assert payload["results"][0]["detail"]["nt_hash"] == REDACTED
    assert payload["results"][0]["detail"]["safe"] == "evidence"
    # Maskeleme kopya üzerinde: ham kanıt sonucu mutate edilmez.
    assert state.results[0]["detail"]["nt_hash"] == original_hash


def test_websocket_subscriber_receives_only_sanitized_payload():
    job_id = "sanitize-ws-job"
    secret = "WS-Gizli-Parola!"
    job_manager.create_job(job_id, "10.0.0.5", module="ad_probe")
    job_manager._job_secrets[job_id] = [secret]

    async def _flow():
        queue = await job_manager.subscribe(job_id)
        await queue.get()                       # ilk durum
        await job_manager.log(job_id, f"LDAP parolası: {secret}")
        payload = await queue.get()             # canlı WebSocket payload'ı
        job_manager.unsubscribe(job_id, queue)
        return payload

    payload = asyncio.run(_flow())
    assert secret not in str(payload)
    assert REDACTED in " ".join(payload["logs"])


def test_terminal_job_forgets_raw_secret():
    job_id = "sanitize-terminal-job"
    job_manager.create_job(job_id, "10.0.0.5", module="ad_probe")
    job_manager._job_secrets[job_id] = ["GizliSifre1!"]
    asyncio.run(job_manager.update(job_id, status=JobStatus.DONE))
    assert job_id not in job_manager._job_secrets

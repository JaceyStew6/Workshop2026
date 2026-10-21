"""Tests de l'agent hôte avec une caméra simulée : cycle de vie, jeton, chien de garde, cas d'échec."""
import sys
import time
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent import create_app  # noqa: E402
from camera import CameraOff, CameraSession, FakeBackend, person_embedding  # noqa: E402

TOKEN = "t" * 32
H = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def env():
    backend = FakeBackend()
    app = create_app(backend, TOKEN)
    yield backend, TestClient(app), app.state.session
    app.state.session.off()


def test_token_is_required_and_checked(env):
    _, c, _ = env
    assert c.get("/v1/health").status_code == 401
    assert c.get("/v1/health", headers={"Authorization": "Bearer faux"}).status_code == 401
    assert c.get("/v1/health", headers=H).status_code == 200


def test_short_token_is_refused():
    with pytest.raises(ValueError):
        create_app(FakeBackend(), "court")


def test_camera_is_off_until_requested_and_embed_needs_it(env):
    backend, c, _ = env
    assert not backend.opened
    assert c.post("/v1/camera/embed", headers=H, json={}).status_code == 409
    assert c.post("/v1/camera/on", headers=H, json={"max_seconds": 30}).status_code == 200
    assert backend.opened
    assert c.post("/v1/camera/off", headers=H).status_code == 200
    assert not backend.opened


def test_same_person_gives_close_embeddings_different_person_does_not(env):
    backend, c, _ = env
    c.post("/v1/camera/on", headers=H, json={"max_seconds": 30})
    backend.set_person("alice")
    a = c.post("/v1/camera/embed", headers=H, json={"frames": 3, "timeout_s": 5}).json()
    backend.set_person("bob")
    b = c.post("/v1/camera/embed", headers=H, json={"frames": 3, "timeout_s": 5}).json()
    assert a["reason"] == "ok" and len(a["embeddings"]) == 3 and len(a["embeddings"][0]) == 128
    ref = person_embedding("alice")
    assert float(np.dot(ref, np.array(a["embeddings"][0]))) > 0.9
    assert float(np.dot(ref, np.array(b["embeddings"][0]))) < 0.5


@pytest.mark.parametrize("reason", ["no_face", "multiple_faces", "too_small", "camera_error"])
def test_rejected_images_never_produce_embeddings(env, reason):
    backend, c, _ = env
    c.post("/v1/camera/on", headers=H, json={"max_seconds": 30})
    backend.set_person("alice", reason=reason)
    r = c.post("/v1/camera/embed", headers=H, json={"frames": 2, "timeout_s": 1}).json()
    assert r["embeddings"] == [] and r["reason"] == reason


def test_empty_room_times_out_without_embedding(env):
    backend, c, _ = env
    c.post("/v1/camera/on", headers=H, json={"max_seconds": 30})
    backend.set_person(None)
    r = c.post("/v1/camera/embed", headers=H, json={"frames": 2, "timeout_s": 1}).json()
    assert r["embeddings"] == [] and r["reason"] == "no_face"


def test_watchdog_turns_camera_off_by_itself():
    backend = FakeBackend()
    s = CameraSession(backend)
    s.on(0.3)
    assert backend.opened
    time.sleep(0.7)
    assert not backend.opened and not s.is_on
    with pytest.raises(CameraOff):
        s.embed(1, 1)


def test_calling_on_twice_does_not_reopen_the_device(env):
    _, c, session = env
    c.post("/v1/camera/on", headers=H, json={"max_seconds": 30})
    c.post("/v1/camera/on", headers=H, json={"max_seconds": 30})
    assert session.opened_total == 1


def test_fake_endpoint_exists_only_with_fake_backend():
    class Real(FakeBackend):  # n'est plus une FakeBackend « pure » : on simule un autre type de backend
        pass
    from camera import Backend

    class NotFake:
        def open(self): ...
        def observe(self): ...
        def close(self): ...

    app = create_app(NotFake(), TOKEN)  # type: ignore[arg-type]
    c = TestClient(app)
    assert c.post("/v1/fake/person", headers=H, json={"name": "x"}).status_code == 404

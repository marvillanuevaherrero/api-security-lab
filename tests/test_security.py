import pytest
from fastapi.testclient import TestClient
from app.main import create_app

@pytest.fixture(params=[False, True], ids=["hardened", "vulnerable"])
def setup(request):
    client = TestClient(create_app(vulnerable=request.param))
    return client, request.param

def auth(client, username="alice"):
    r = client.post("/login", json={"username": username, "password": f"{username}-demo"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}

def test_health(setup):
    client, vulnerable = setup
    assert client.get("/health").json()["mode"] == ("vulnerable" if vulnerable else "hardened")

def test_missing_auth(setup):
    client, _ = setup
    assert client.get("/users/alice").status_code == 401

def test_cross_account_access(setup):
    client, vulnerable = setup
    result = client.get("/users/bob", headers=auth(client))
    assert result.status_code == (200 if vulnerable else 403)

def test_mass_assignment(setup):
    client, vulnerable = setup
    result = client.patch("/users/alice", headers=auth(client), json={"display_name": "New", "role": "admin"})
    assert result.status_code == (200 if vulnerable else 422)
    assert client.get("/users/alice", headers=auth(client)).json()["role"] == ("admin" if vulnerable else "user")

def test_valid_update(setup):
    client, _ = setup
    assert client.patch("/users/alice", headers=auth(client), json={"display_name": "Changed"}).status_code == 200

def test_rate_limit_bypass(setup):
    client, vulnerable = setup
    statuses = []
    for i in range(5):
        r = client.post("/login", headers={"X-Forwarded-For": f"198.51.100.{i+1}"}, json={"username": "alice", "password": "wrong"})
        statuses.append(r.status_code)
    assert statuses == ([401] * 5 if vulnerable else [401, 401, 401, 429, 429])

def test_events_not_public_in_hardened(setup):
    client, vulnerable = setup
    result = client.get("/events", headers=auth(client))
    assert result.status_code == (200 if vulnerable else 403)

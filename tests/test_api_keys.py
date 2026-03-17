import pytest


def _get_token(client, email="user@test.com", password="pass123"):
    client.post("/auth/signup", json={"email": email, "password": password})
    r = client.post("/auth/login", data={"username": email, "password": password})
    return r.json()["access_token"]


def test_create_key(client):
    token = _get_token(client)
    r = client.post("/keys/", json={"name": "my key"}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201
    data = r.json()
    assert data["name"] == "my key"
    assert data["key"].startswith("sk_")


def test_list_keys(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    client.post("/keys/", json={"name": "key1"}, headers=headers)
    client.post("/keys/", json={"name": "key2"}, headers=headers)
    r = client.get("/keys/", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 2


def test_revoke_key(client):
    token = _get_token(client)
    headers = {"Authorization": f"Bearer {token}"}
    create_r = client.post("/keys/", json={"name": "to-revoke"}, headers=headers)
    key_id = create_r.json()["id"]
    r = client.delete(f"/keys/{key_id}", headers=headers)
    assert r.status_code == 204
    keys = client.get("/keys/", headers=headers).json()
    assert not keys[0]["is_active"]


def test_no_auth(client):
    r = client.get("/keys/")
    assert r.status_code == 401

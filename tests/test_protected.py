def _create_api_key(client):
    client.post("/auth/signup", json={"email": "u@t.com", "password": "pass"})
    token = client.post("/auth/login", data={"username": "u@t.com", "password": "pass"}).json()["access_token"]
    key_r = client.post("/keys/", json={"name": "test"}, headers={"Authorization": f"Bearer {token}"})
    return key_r.json()["key"]


def test_access_with_valid_key(client):
    key = _create_api_key(client)
    r = client.get("/api/v1/data", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert r.json()["message"] == "Access granted"


def test_access_without_key(client):
    r = client.get("/api/v1/data")
    assert r.status_code == 401


def test_access_with_invalid_key(client):
    r = client.get("/api/v1/data", headers={"X-API-Key": "sk_fake"})
    assert r.status_code == 401

def test_signup(client):
    r = client.post("/auth/signup", json={"email": "test@example.com", "password": "secret123"})
    assert r.status_code == 201
    assert r.json()["email"] == "test@example.com"


def test_signup_duplicate(client):
    client.post("/auth/signup", json={"email": "test@example.com", "password": "secret123"})
    r = client.post("/auth/signup", json={"email": "test@example.com", "password": "other"})
    assert r.status_code == 400


def test_login(client):
    client.post("/auth/signup", json={"email": "user@example.com", "password": "pass123"})
    r = client.post("/auth/login", data={"username": "user@example.com", "password": "pass123"})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_wrong_password(client):
    client.post("/auth/signup", json={"email": "user@example.com", "password": "pass123"})
    r = client.post("/auth/login", data={"username": "user@example.com", "password": "wrong"})
    assert r.status_code == 401

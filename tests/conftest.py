import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch, MagicMock

import app.database as db_module
from app.database import Base, get_db
from app.main import app

SQLALCHEMY_TEST_URL = "sqlite:///./test.db"

test_engine = create_engine(SQLALCHEMY_TEST_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Bootstrap database module with test engine so imports work
db_module._engine = test_engine
db_module._SessionLocal = TestingSessionLocal


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db():
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    mock_redis = MagicMock()
    mock_redis.pipeline.return_value.execute.return_value = [1, 30]

    app.dependency_overrides[get_db] = override_get_db
    with patch("app.redis_client.get_redis", return_value=mock_redis):
        with patch("app.middleware.rate_limit.get_redis", return_value=mock_redis):
            with TestClient(app) as c:
                yield c
    app.dependency_overrides.clear()

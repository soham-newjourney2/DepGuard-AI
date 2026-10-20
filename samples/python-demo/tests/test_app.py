import pytest

from app import app


@pytest.fixture
def client():
    return app.test_client()


def test_import(client):
    assert client.post("/import", data="a: 1").json == {"a": 1}

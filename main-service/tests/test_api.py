import pytest


@pytest.mark.fixtures({"client": "client"})
def test_health_check_returns_correct_response(fixtures):
    result = fixtures.client.get("/health-check")

    assert result.json() == "Hello, world!"

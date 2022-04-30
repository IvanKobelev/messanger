import pytest
from types import SimpleNamespace
from fastapi.testclient import TestClient

from src.views import app


@pytest.fixture
def fixtures(request):
    """Collection of fixtures declared via 'fixtures' mark."""
    fixtures = SimpleNamespace()
    if marker := request.node.get_closest_marker("fixtures"):
        for attr_name, fixture_config in marker.args[0].items():
            fixture = request.getfixturevalue(fixture_config)
            setattr(fixtures, attr_name, fixture)
    return fixtures


@pytest.fixture
def client():
    return TestClient(app)

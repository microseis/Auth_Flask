import pytest

from src.main import create_app


@pytest.fixture
def app():
    app = create_app()
    return app

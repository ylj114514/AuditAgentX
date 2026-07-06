"""pytest 全局夹具：确保测试前数据库表已建好。"""
import pytest

from backend.database import init_db


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    init_db()
    yield

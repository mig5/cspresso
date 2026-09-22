import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--run-browser",
        action="store_true",
        help="Run local Chromium integration tests (browser required)",
    )
    parser.addoption(
        "--run-network",
        action="store_true",
        help="Run optional public-site smoke tests",
    )


def pytest_collection_modifyitems(config, items):
    for item in items:
        for marker, option in [
            ("browser", "--run-browser"),
            ("network", "--run-network"),
        ]:
            if marker in item.keywords and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"Enable {option}"))

"""UT-SMOKE-001: the package imports and exposes a version string."""

import mnemowall


def test_package_has_version() -> None:
    assert isinstance(mnemowall.__version__, str)
    assert mnemowall.__version__

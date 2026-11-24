import pytest

import storage.files as storage
from crypto import kdf


@pytest.fixture(autouse=True)
def fast_scrypt(request, monkeypatch):
    """Cheap scrypt for the tests, otherwise every register/login takes ~1 s.

    The real value (2**17) stays in kdf.py. Tests marked with prod_params
    skip this and run with the production cost.
    """
    if request.node.get_closest_marker("prod_params"):
        return
    monkeypatch.setattr(kdf, "SCRYPT_N", 2 ** 10)


@pytest.fixture
def isolated_storage(tmp_path, monkeypatch):
    """Point the storage layer to a temp folder so tests never touch real data."""
    monkeypatch.setattr(storage, "DATA_DIR", tmp_path)
    return tmp_path

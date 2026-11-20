import os

import pytest

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CCX26_DIR = os.path.join(DATA_DIR, "ccx26")


@pytest.fixture
def ccx26_dir():
    """Synthetic logs in the IBM Content Cortex 26 ce_system*.log format."""
    return CCX26_DIR


CCX26_VARIANTS_DIR = os.path.join(DATA_DIR, "ccx26_variants")


@pytest.fixture
def ccx26_variants_dir():
    """Synthetic CCX 26 log with messages that differ only in variable parts."""
    return CCX26_VARIANTS_DIR

"""Pytest fixture for the complete in-memory AoR pipeline."""

from pathlib import Path

import pytest

from .pipeline import FullPipeline


@pytest.fixture
def full_pipeline(tmp_path: Path) -> FullPipeline:
    return FullPipeline(tmp_path)

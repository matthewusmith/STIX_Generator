import json
from pathlib import Path

import pytest

GOLDEN = Path(__file__).resolve().parents[1] / "data" / "golden" / "autonomous-ai-cyber-attack-campaign.json"


@pytest.fixture
def golden_dict() -> dict:
    return json.loads(GOLDEN.read_text(encoding="utf-8"))

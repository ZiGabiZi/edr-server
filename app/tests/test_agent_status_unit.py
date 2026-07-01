from datetime import datetime, timedelta, timezone

from app.services.agent_service import _derive_status


def make_agent(seconds_ago: float) -> dict:
    last_seen = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()
    return {"last_seen": last_seen}


def test_fresh_heartbeat_is_online():
    assert _derive_status(make_agent(0)) == "online"


def test_just_under_stale_threshold_is_online():
    assert _derive_status(make_agent(29.9)) == "online"


def test_at_stale_threshold_is_degraded():
    # boundary exact: conditia e strict "<", deci egalitatea cade pe degraded
    assert _derive_status(make_agent(30.0)) == "degraded"


def test_just_under_offline_threshold_is_degraded():
    assert _derive_status(make_agent(89.9)) == "degraded"


def test_at_offline_threshold_is_offline():
    assert _derive_status(make_agent(90.0)) == "offline"


def test_long_dead_agent_is_offline():
    # scenariul exact din bug-ul original: agent mort de o ora
    assert _derive_status(make_agent(3600)) == "offline"


def test_missing_last_seen_is_unknown():
    assert _derive_status({}) == "unknown"
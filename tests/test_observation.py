"""Tests for the Observation layer."""

import pytest

from protector_stack.observation.normalizer import EventNormalizer
from protector_stack.observation.collector import EventCollector, reset_collector
from protector_stack.observation.schemas import EventType


@pytest.fixture(autouse=True)
def reset():
    reset_collector()
    yield
    reset_collector()


def test_normalizer_process_spawn():
    norm = EventNormalizer()
    event = norm.normalize(
        {"type": "process_spawn", "pid": 1234, "name": "python.exe"},
        source="test",
    )
    assert event.event_type == EventType.PROCESS_SPAWN
    assert "1234" in event.actor_id or event.actor_id == "unknown"
    assert event.source == "test"


def test_normalizer_unknown_type():
    norm = EventNormalizer()
    event = norm.normalize({"type": "totally_unknown"}, source="test")
    assert event.event_type == EventType.UNKNOWN


def test_normalizer_prompt_truncation():
    norm = EventNormalizer()
    long_prompt = "A" * 500
    event = norm.normalize({"type": "model_inference", "prompt": long_prompt}, source="test")
    stored = event.raw_data.get("prompt", "")
    assert len(stored) <= 210  # 200 chars + ellipsis


def test_normalizer_auto_description_file_created():
    norm = EventNormalizer()
    event = norm.normalize(
        {"type": "file_created", "path": "/tmp/test.txt"}, source="test"
    )
    assert "file created" in event.description.lower()
    assert "/tmp/test.txt" in event.description


def test_collector_submit_and_handler():
    collector = EventCollector()
    received = []

    def handler(event):
        received.append(event)

    collector.register_handler(handler)
    event = collector.submit(
        {"type": "process_spawn", "pid": 9999, "name": "test.exe"},
        source="test",
    )
    assert len(received) == 1
    assert received[0].event_id == event.event_id


def test_collector_multiple_handlers():
    collector = EventCollector()
    calls_a = []
    calls_b = []
    collector.register_handler(lambda e: calls_a.append(e))
    collector.register_handler(lambda e: calls_b.append(e))
    collector.submit({"type": "system_status"}, source="test")
    assert len(calls_a) == 1
    assert len(calls_b) == 1


def test_collector_handler_exception_doesnt_crash():
    collector = EventCollector()

    def bad_handler(event):
        raise RuntimeError("Intentional error in handler")

    collector.register_handler(bad_handler)
    # Should not raise
    collector.submit({"type": "system_status"}, source="test")


def test_collector_stats():
    collector = EventCollector()
    collector.submit({"type": "system_status"}, source="test")
    collector.submit({"type": "system_status"}, source="test")
    stats = collector.stats()
    assert stats["events_processed"] >= 2

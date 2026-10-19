"""
kafka/stream.py
================
Lightweight in-process event-stream abstraction.

Multi-Agent SOC Project -- Stage 4: Real-Time Event Streaming

WHY THIS FILE EXISTS
--------------------
Apache Kafka is a powerful distributed event broker, but it requires a running
broker process (and Java).  For a controlled college demonstration that must
run entirely on a local Windows machine with no external services, we implement
the same producer / consumer abstraction using Python's built-in ``queue.Queue``
as the transport layer.

The StreamBroker class exposes:
    broker.get_producer(topic)  -> QueueProducer
    broker.get_consumer(topic)  -> QueueConsumer

Both QueueProducer and QueueConsumer have the same send() / poll() interface
that producer.py and consumer.py use.  If a real Kafka broker is available in
the future, only this file needs to change -- the caller code stays identical.

TRANSPORT MODES
---------------
  "queue"  -- in-process Python Queue (zero setup, works on any machine)
  "kafka"  -- real Kafka broker via kafka-python (requires Kafka + Java)

The transport is selected by config.DEFAULT_TRANSPORT and can be
overridden on the command line with --transport kafka.
"""

import json
import queue
import threading
from typing import Optional


# ---------------------------------------------------------------------------
# In-process Queue transport
# ---------------------------------------------------------------------------

_BROKERS: dict = {}          # topic -> queue.Queue
_BROKER_LOCK = threading.Lock()


def _get_topic_queue(topic: str) -> queue.Queue:
    """Return (or create) the shared Queue for a named topic."""
    with _BROKER_LOCK:
        if topic not in _BROKERS:
            _BROKERS[topic] = queue.Queue()
        return _BROKERS[topic]


class QueueProducer:
    """
    Thin producer wrapper around a Python Queue.

    Mimics the interface of a Kafka producer so that producer.py
    does not need to know about the underlying transport.
    """

    def __init__(self, topic: str):
        self._topic = topic
        self._q = _get_topic_queue(topic)

    def send(self, event: dict) -> None:
        """Serialise ``event`` to JSON and push it onto the queue."""
        self._q.put(json.dumps(event, ensure_ascii=False))

    def flush(self) -> None:
        """No-op for queue transport (messages are synchronous)."""
        pass

    def close(self) -> None:
        """No-op for queue transport."""
        pass


class QueueConsumer:
    """
    Thin consumer wrapper around a Python Queue.

    Mimics the interface of a Kafka consumer so that consumer.py
    does not need to know about the underlying transport.
    """

    def __init__(self, topic: str, timeout_s: float = 5.0):
        self._topic = topic
        self._q = _get_topic_queue(topic)
        self._timeout = timeout_s
        self._running = True

    def poll(self, timeout_s: Optional[float] = None) -> Optional[dict]:
        """
        Block until an event arrives or timeout expires.

        Returns:
            Parsed event dict, or None on timeout.
        """
        t = timeout_s if timeout_s is not None else self._timeout
        try:
            raw = self._q.get(block=True, timeout=t)
            return json.loads(raw)
        except queue.Empty:
            return None

    def close(self) -> None:
        self._running = False


# ---------------------------------------------------------------------------
# Kafka transport (optional; requires kafka-python + running broker)
# ---------------------------------------------------------------------------

class KafkaProducerWrapper:
    """Thin wrapper around kafka-python KafkaProducer."""

    def __init__(self, topic: str, bootstrap_servers: str):
        try:
            from kafka import KafkaProducer as _KP
        except ImportError:
            raise ImportError(
                "kafka-python is not installed. "
                "Run: pip install kafka-python   "
                "or use --transport queue for the built-in simulation."
            )

        self._topic = topic
        self._producer = _KP(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8"),
            acks="all",
        )

    def send(self, event: dict) -> None:
        self._producer.send(self._topic, value=event)

    def flush(self) -> None:
        self._producer.flush()

    def close(self) -> None:
        self._producer.close()


class KafkaConsumerWrapper:
    """Thin wrapper around kafka-python KafkaConsumer."""

    def __init__(self, topic: str, bootstrap_servers: str, group_id: str):
        try:
            from kafka import KafkaConsumer as _KC
        except ImportError:
            raise ImportError(
                "kafka-python is not installed. "
                "Run: pip install kafka-python   "
                "or use --transport queue for the built-in simulation."
            )

        self._consumer = _KC(
            topic,
            bootstrap_servers=bootstrap_servers,
            group_id=group_id,
            value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            consumer_timeout_ms=5000,
        )

    def poll(self, timeout_s: float = 5.0) -> Optional[dict]:
        """Return the next available message or None on timeout."""
        msg = next(iter(self._consumer), None)
        if msg is not None:
            return msg.value
        return None

    def close(self) -> None:
        self._consumer.close()


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def make_producer(transport: str, topic: str, bootstrap_servers: str = ""):
    """Return an appropriate producer for the chosen transport."""
    if transport == "kafka":
        return KafkaProducerWrapper(topic, bootstrap_servers)
    return QueueProducer(topic)


def make_consumer(
    transport: str,
    topic: str,
    bootstrap_servers: str = "",
    group_id: str = "",
    timeout_s: float = 5.0,
):
    """Return an appropriate consumer for the chosen transport."""
    if transport == "kafka":
        return KafkaConsumerWrapper(topic, bootstrap_servers, group_id)
    return QueueConsumer(topic, timeout_s=timeout_s)

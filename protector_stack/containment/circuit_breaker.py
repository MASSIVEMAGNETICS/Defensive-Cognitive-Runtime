"""
Containment Layer: Circuit Breaker
------------------------------------
Implements a circuit-breaker pattern for high-risk action streams.

When a circuit breaker trips:
- Further actions of the same category are blocked until reset
- An alert is raised
- Human review is required to reset

States: CLOSED (normal) → OPEN (tripped) → HALF-OPEN (testing) → CLOSED
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from protector_stack.utils.logging import get_logger

log = get_logger(__name__)


class CircuitState(str, Enum):
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Tripped — blocking
    HALF_OPEN = "half_open" # Testing recovery


@dataclass
class CircuitBreakerConfig:
    failure_threshold: int = 3       # Consecutive failures before opening
    success_threshold: int = 2       # Successes in HALF-OPEN to close
    timeout_seconds: float = 60.0    # Time before OPEN → HALF-OPEN
    scope: str = "default"


@dataclass
class CircuitBreaker:
    """A circuit breaker for a named scope."""
    config: CircuitBreakerConfig
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[float] = None
    trip_reason: str = ""

    def is_open(self) -> bool:
        """Return True if the circuit is OPEN (blocking)."""
        if self.state == CircuitState.OPEN:
            if (
                self.last_failure_time
                and time.monotonic() - self.last_failure_time >= self.config.timeout_seconds
            ):
                self.state = CircuitState.HALF_OPEN
                self.success_count = 0
                log.info(f"CircuitBreaker '{self.config.scope}' → HALF-OPEN (testing recovery)")
                return False
            return True
        return False

    def record_failure(self, reason: str = "") -> None:
        """Record a failure event."""
        self.failure_count += 1
        self.last_failure_time = time.monotonic()
        self.success_count = 0
        self.trip_reason = reason

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.OPEN
            log.warning(
                f"CircuitBreaker '{self.config.scope}' → OPEN again "
                f"(failed during recovery): {reason}"
            )
        elif (
            self.state == CircuitState.CLOSED
            and self.failure_count >= self.config.failure_threshold
        ):
            self.state = CircuitState.OPEN
            log.warning(
                f"CircuitBreaker '{self.config.scope}' TRIPPED → OPEN "
                f"after {self.failure_count} failures: {reason}"
            )

    def record_success(self) -> None:
        """Record a success event."""
        self.success_count += 1
        if self.state == CircuitState.HALF_OPEN:
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.trip_reason = ""
                log.info(f"CircuitBreaker '{self.config.scope}' → CLOSED (recovered)")

    def force_reset(self, operator_id: str) -> None:
        """Manually reset the circuit breaker (requires human operator action)."""
        prev = self.state
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.trip_reason = ""
        log.info(
            f"CircuitBreaker '{self.config.scope}' manually reset "
            f"from {prev} by {operator_id}"
        )


class CircuitBreakerRegistry:
    """Manages multiple circuit breakers by scope."""

    def __init__(self) -> None:
        self._breakers: dict[str, CircuitBreaker] = {}

    def get(self, scope: str, **config_kwargs) -> CircuitBreaker:
        """Get or create a circuit breaker for the given scope."""
        if scope not in self._breakers:
            cfg = CircuitBreakerConfig(scope=scope, **config_kwargs)
            self._breakers[scope] = CircuitBreaker(config=cfg)
        return self._breakers[scope]

    def is_scope_blocked(self, scope: str) -> bool:
        """Return True if the scope's circuit is currently OPEN."""
        breaker = self._breakers.get(scope)
        if breaker is None:
            return False
        return breaker.is_open()

    def get_status(self) -> dict[str, str]:
        """Return current state of all circuit breakers."""
        return {scope: cb.state.value for scope, cb in self._breakers.items()}

    def reset(self, scope: str, operator_id: str) -> bool:
        """Reset a circuit breaker by scope. Returns True if found."""
        breaker = self._breakers.get(scope)
        if breaker is None:
            return False
        breaker.force_reset(operator_id)
        return True


# Singleton
_registry: Optional[CircuitBreakerRegistry] = None


def get_circuit_breaker_registry() -> CircuitBreakerRegistry:
    global _registry
    if _registry is None:
        _registry = CircuitBreakerRegistry()
    return _registry

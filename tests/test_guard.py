"""Strict regression tests for the proof-of-work guard."""

from __future__ import annotations

import hashlib
import time

import pytest

from pow.guard import (
    MAX_DIFFICULTY,
    check_challenge,
    consume_challenge,
    counter_valid,
    issue_challenge,
    pow_batch,
    solve,
    target_for,
    validate_policy,
)

POLICY = {
    "max_difficulty": 12,
    "challenge_ttl": 60,
    "bind_client": True,
}


def _digest(nonce: str) -> int:
    return int.from_bytes(hashlib.sha256(nonce.encode("utf-8")).digest(), "big")


def _new_challenge(
    client: str = "alice",
    difficulty: int = 4,
    now: float | None = None,
    ttl: float = 60,
):
    issued_at = time.time() if now is None else now
    store: dict[str, dict] = {}
    challenge = issue_challenge(store, client, difficulty, issued_at, ttl)
    return store, challenge


def _request(
    client: str,
    difficulty: int = 4,
    now: float | None = None,
    ttl: float = 60,
) -> dict:
    issued_at = time.time() if now is None else now
    store, challenge = _new_challenge(client, difficulty, issued_at, ttl)
    base = f"{client}:{challenge['id']}"
    counter = solve(base, difficulty)
    return {
        "client": client,
        "store": store,
        "challenge": challenge,
        "nonce": f"{base}:{counter}",
    }


def test_defect_01_target_scale_and_zero_difficulty():
    with pytest.raises(ValueError):
        target_for(0)

    assert target_for(1) == 1 << 255
    assert target_for(4) == 1 << 252
    assert target_for(MAX_DIFFICULTY) == 1 << (256 - MAX_DIFFICULTY)


def test_defect_02_difficulty_cap():
    with pytest.raises(ValueError):
        target_for(MAX_DIFFICULTY + 1)

    with pytest.raises(ValueError):
        target_for(10_000)


def test_defect_03_compare_digest_strictly_below_target():
    nonce = "alice:0"
    exact = _digest(nonce)

    assert counter_valid(nonce, exact) is False
    assert counter_valid(nonce, exact + 1) is True
    assert counter_valid(nonce, 0) is False
    assert counter_valid(nonce, 1 << 256) is True


def test_defect_04_challenge_difficulty_is_authoritative():
    store, challenge = _new_challenge(client="alice", difficulty=8)
    challenge_id = challenge["id"]

    assert challenge["difficulty"] == 8
    challenge["difficulty"] = 0
    assert store[challenge_id]["difficulty"] == 8
    assert check_challenge(store, challenge, time.time()) is False
    with pytest.raises(ValueError):
        consume_challenge(store, challenge)


def test_defect_05_challenge_is_bound_to_client():
    store, challenge = _new_challenge(client="alice")
    challenge_id = challenge["id"]

    challenge["client"] = "mallory"
    assert store[challenge_id]["client"] == "alice"
    assert check_challenge(store, challenge, time.time()) is False
    with pytest.raises(ValueError):
        consume_challenge(store, challenge)


def test_defect_06_consumption_deletes_challenge():
    store, challenge = _new_challenge(client="alice")
    challenge_id = challenge["id"]

    consumed = consume_challenge(store, challenge)
    assert consumed["id"] == challenge_id
    assert challenge_id not in store
    with pytest.raises(ValueError):
        consume_challenge(store, challenge)


def test_defect_07_consumption_rejects_expired_challenge():
    store, challenge = _new_challenge(now=time.time() - 120, ttl=10)

    assert check_challenge(store, challenge, time.time()) is False
    with pytest.raises(ValueError):
        consume_challenge(store, challenge)


def test_defect_08_solve_uses_the_same_target_as_validation():
    base = "solver"
    difficulty = 4
    target = target_for(difficulty)

    counter = solve(base, difficulty)
    assert counter >= 0
    assert counter_valid(f"{base}:{counter}", target) is True
    for earlier in range(counter):
        assert counter_valid(f"{base}:{earlier}", target) is False


def test_defect_09_policy_rejects_unbounded_difficulty():
    assert validate_policy(POLICY) == []

    over_cap = {
        "max_difficulty": MAX_DIFFICULTY + 1,
        "challenge_ttl": 60,
        "bind_client": True,
    }
    missing_cap = {
        "challenge_ttl": 60,
        "bind_client": True,
    }

    assert "max_difficulty_exceeds_limit" in validate_policy(over_cap)
    assert "max_difficulty_missing" in validate_policy(missing_cap)


def test_defect_10_batch_requests_do_not_share_state():
    now = time.time()
    first = _request("alice", now=now)
    second = _request("bob", now=now)

    result = pow_batch([first, second], POLICY, now)

    assert result["problems"] == []
    assert result["results"] == [True, True]
    assert result["accepted"] == 2


def test_valid_proof_passes():
    now = time.time()
    store, challenge = _new_challenge(client="alice", difficulty=4, now=now)
    base = f"alice:{challenge['id']}"
    counter = solve(base, 4)
    nonce = f"{base}:{counter}"

    assert counter_valid(nonce, target_for(4)) is True
    assert check_challenge(store, challenge, now + 0.5) is True
    consumed = consume_challenge(store, challenge)
    assert consumed["client"] == "alice"
    assert consumed["difficulty"] == 4


def test_zero_difficulty_is_rejected_everywhere():
    with pytest.raises(ValueError):
        target_for(0)

    store: dict[str, dict] = {}
    with pytest.raises(ValueError):
        issue_challenge(store, "alice", 0, time.time(), 60)

    with pytest.raises(ValueError):
        solve("alice:0", 0)


def test_challenge_is_single_use():
    store, challenge = _new_challenge(client="alice")

    consume_challenge(store, challenge)
    assert check_challenge(store, challenge, time.time()) is False
    with pytest.raises(ValueError):
        consume_challenge(store, challenge)


def test_expired_challenge_is_rejected():
    issued_at = time.time()
    store, challenge = _new_challenge(now=issued_at, ttl=10)

    assert check_challenge(store, challenge, issued_at + 9.5) is True
    assert check_challenge(store, challenge, issued_at + 10) is False
    assert check_challenge(store, challenge, issued_at + 11) is False

    expired_store, expired_challenge = _new_challenge(
        now=time.time() - 120,
        ttl=10,
    )
    with pytest.raises(ValueError):
        consume_challenge(expired_store, expired_challenge)


def test_batch_matches_individual_validation():
    now = time.time()
    expected: list[bool] = []

    for client in ("alice", "bob"):
        request = _request(client, now=now)
        single = pow_batch([request], POLICY, now)
        assert single["results"] == [True]
        expected.append(single["results"][0])

    first = _request("alice", now=now)
    second = _request("bob", now=now)
    combined = pow_batch([first, second], POLICY, now)

    assert combined["results"] == expected
    assert combined["accepted"] == sum(expected)
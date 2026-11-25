"""Proof-of-work guard.

The functions below implement the server side of a hash-based proof-of-work
handshake: target derivation, proof checking, challenge lifecycle, solving,
policy validation, and batch validation.

Each defect from the task statement is addressed where it belongs:

1.  target scale / zero difficulty  -> target_for
2.  unbounded difficulty             -> target_for
3.  proof comparison                 -> counter_valid
4.  client-supplied difficulty       -> issue_challenge / check_challenge /
                                        consume_challenge use the store record
5.  challenge not bound to client    -> check_challenge / consume_challenge
6.  consumption does not delete      -> consume_challenge
7.  consumption ignores expiry       -> consume_challenge
8.  solve uses a different target    -> solve
9.  policy does not cap difficulty   -> validate_policy
10. batch shares challenge state     -> pow_batch
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Mapping, MutableMapping

HASH_BITS = 256
MAX_DIFFICULTY = 32


def _is_number(value) -> bool:
    """True for real numbers, excluding bool (which is an int subclass)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _record_for(store, challenge):
    """Return the authoritative record for a presentation, or None.

    Malformed presentations (unhashable ids, non-mapping values) simply have
    no record rather than raising.
    """
    if not isinstance(store, Mapping) or not isinstance(challenge, Mapping):
        return None
    challenge_id = challenge.get("id")
    try:
        record = store.get(challenge_id)
    except TypeError:  # unhashable challenge id
        return None
    return record if isinstance(record, Mapping) else None


def target_for(difficulty: int) -> int:
    """Return the 256-bit acceptance target for a server difficulty.

    difficulty must be an integer in the closed range 1..MAX_DIFFICULTY.
    The target is 1 << (HASH_BITS - difficulty). Any other value raises
    ValueError, including zero, negative values, bools, and values above the
    cap.
    """
    # Defect 1: a difficulty of zero used to shift by 256 and produce a target
    # of zero, which no digest can ever beat.  Defect 2: an unbounded
    # difficulty made the shift negative (or the target zero) and likewise
    # unsolvable.  Rejecting everything outside 1..MAX_DIFFICULTY fixes both.
    if not isinstance(difficulty, int) or isinstance(difficulty, bool):
        raise ValueError(f"difficulty must be an integer, got {difficulty!r}")
    if difficulty < 1 or difficulty > MAX_DIFFICULTY:
        raise ValueError(
            f"difficulty must be in 1..{MAX_DIFFICULTY}, got {difficulty!r}"
        )
    return 1 << (HASH_BITS - difficulty)


def counter_valid(nonce: str, target: int) -> bool:
    """Return True only when the proof digest is strictly below target.

    nonce is the complete candidate string, including its trailing counter.
    Its UTF-8 bytes are hashed with SHA-256, and the digest is interpreted as
    a big-endian integer. A target less than or equal to zero is never valid.
    """
    if not _is_number(target) or target <= 0:
        return False
    digest = int.from_bytes(hashlib.sha256(nonce.encode("utf-8")).digest(), "big")
    # Defect 3: check the digest against the target instead of merely checking
    # that the counter looked plausible.  The comparison is strict.
    return digest < target


def issue_challenge(store, client, difficulty, now, ttl) -> dict:
    """Issue a server-controlled challenge and return its presentation copy.

    store is a mutable mapping keyed by challenge id. client is the only client
    allowed to use the challenge. difficulty is chosen by server policy and
    must satisfy target_for. now and ttl are expressed in seconds. The
    authoritative record is kept in store and contains id, client, difficulty,
    issued_at, expires_at, and used.
    """
    # Defect 4: the difficulty is validated here, by the server, and only the
    # validated value is ever stored.
    target_for(difficulty)
    if not _is_number(ttl) or ttl <= 0:
        raise ValueError(f"ttl must be a positive number, got {ttl!r}")

    challenge_id = secrets.token_hex(16)
    while challenge_id in store:
        challenge_id = secrets.token_hex(16)

    record = {
        "id": challenge_id,
        "client": client,
        "difficulty": difficulty,
        "issued_at": now,
        "expires_at": now + ttl,
        "used": False,
    }
    store[challenge_id] = record
    # Return a copy: the caller's presentation must not be able to mutate the
    # authoritative record (defects 4 and 5).
    return dict(record)


def check_challenge(store, challenge, now) -> bool:
    """Return True only for a live, unused, correctly bound challenge.

    The id must still exist in store, used must be False, now must be strictly
    less than expires_at, and the presented client and difficulty must both
    match the authoritative record in store.
    """
    if not isinstance(challenge, Mapping) or not isinstance(store, Mapping):
        return False

    record = _record_for(store, challenge)
    if record is None:
        return False
    if record.get("used") is not False:
        return False

    expires_at = record.get("expires_at")
    if not _is_number(now) or not _is_number(expires_at) or not now < expires_at:
        return False

    # Defects 4 and 5: trust the stored client and difficulty, never the
    # values presented by the caller.
    presented_difficulty = challenge.get("difficulty")
    if not isinstance(presented_difficulty, int) or isinstance(
        presented_difficulty, bool
    ):
        return False
    if challenge.get("client") != record.get("client"):
        return False
    if presented_difficulty != record.get("difficulty"):
        return False
    return True


def consume_challenge(store, challenge) -> dict:
    """Consume a challenge, delete it from store, and return the record.

    The wall clock decides expiry. Raise ValueError for an unknown challenge,
    an already consumed challenge, an expired challenge, or a presentation
    whose client or difficulty differs from the authoritative record.
    """
    if not isinstance(challenge, Mapping) or not isinstance(
        store, MutableMapping
    ):
        raise ValueError("invalid challenge presentation")

    record = _record_for(store, challenge)
    if record is None:
        # Unknown and already-consumed challenges are indistinguishable
        # because consumption deletes the record (defect 6).
        raise ValueError("unknown or already consumed challenge")
    if record.get("used") is not False:
        raise ValueError("challenge has already been used")

    # Defect 7: expiry is enforced against the real wall clock at consumption
    # time, not just at presentation time.
    expires_at = record.get("expires_at")
    if not _is_number(expires_at) or not time.time() < expires_at:
        raise ValueError("challenge has expired")

    presented_difficulty = challenge.get("difficulty")
    if not isinstance(presented_difficulty, int) or isinstance(
        presented_difficulty, bool
    ):
        raise ValueError("challenge difficulty mismatch")
    if challenge.get("client") != record.get("client"):
        raise ValueError("challenge client mismatch")
    if presented_difficulty != record.get("difficulty"):
        raise ValueError("challenge difficulty mismatch")

    # Defect 6: a challenge is single use, so it is removed from the store.
    del store[challenge["id"]]
    return dict(record)


def solve(nonce: str, difficulty: int) -> int:
    """Return the smallest counter whose proof meets the difficulty target.

    Counters start at zero. For each counter c the candidate string is
    nonce + ":" + str(c), and it is checked with counter_valid against
    target_for(difficulty). Difficulty validation follows target_for.
    """
    # Defect 8: derive the target exactly the way validation will, instead of
    # using a separate (and disagreeing) notion of the target.
    target = target_for(difficulty)
    counter = 0
    while True:
        if counter_valid(f"{nonce}:{counter}", target):
            return counter
        counter += 1


def validate_policy(policy) -> list[str]:
    """Return policy problems in deterministic order.

    Labels, in order: max_difficulty_missing for an absent or non-positive
    max_difficulty, max_difficulty_exceeds_limit for a cap above
    MAX_DIFFICULTY, challenge_ttl_invalid for an absent or non-positive
    challenge_ttl, and client_binding_required when bind_client is not True.
    A sound policy returns an empty list.
    """
    if not isinstance(policy, Mapping):
        policy = {}

    problems: list[str] = []

    max_difficulty = policy.get("max_difficulty")
    if not _is_number(max_difficulty) or max_difficulty <= 0:
        problems.append("max_difficulty_missing")
    elif max_difficulty > MAX_DIFFICULTY:
        # Defect 9: an outsized cap is rejected instead of accepted blindly.
        problems.append("max_difficulty_exceeds_limit")

    challenge_ttl = policy.get("challenge_ttl")
    if not _is_number(challenge_ttl) or challenge_ttl <= 0:
        problems.append("challenge_ttl_invalid")

    if policy.get("bind_client") is not True:
        problems.append("client_binding_required")

    return problems


def _validate_request(request, now) -> bool:
    """Validate one batch request against its own challenge state."""
    if not isinstance(request, Mapping):
        return False

    client = request.get("client")
    store = request.get("store")
    challenge = request.get("challenge")
    nonce = request.get("nonce")

    if not isinstance(store, MutableMapping) or not isinstance(challenge, Mapping):
        return False
    if not isinstance(nonce, str):
        return False

    record = _record_for(store, challenge)
    if record is None:
        return False

    # The authoritative difficulty comes from the server record.
    try:
        target = target_for(record.get("difficulty"))
    except ValueError:
        return False

    # The request's client must be the client the challenge was issued to;
    # the authoritative client is the stored one, not the presentation.
    if client != record.get("client"):
        return False

    try:
        if not check_challenge(store, challenge, now):
            return False
        if not counter_valid(nonce, target):
            return False
        consume_challenge(store, challenge)
    except (TypeError, ValueError):
        return False
    return True


def pow_batch(requests, policy, now) -> dict:
    """Validate batch requests independently, without shared challenge state.

    Each request mapping has client, store, challenge, and nonce. A request
    succeeds only when its challenge is live and bound, its proof meets
    target_for of the authoritative difficulty, and consumption succeeds.
    Per-request failures are reported as False rather than aborting the batch.
    Return results (list of bool), accepted (int), and problems
    (validate_policy output). An invalid policy rejects the whole batch.
    """
    if not isinstance(requests, (list, tuple)):
        requests = list(requests)

    problems = validate_policy(policy)
    if problems:
        # An invalid policy rejects the whole batch.
        return {"results": [False] * len(requests), "accepted": 0, "problems": problems}

    # Defect 10: every request is validated against its own store, challenge,
    # and nonce.  No challenge state is carried between iterations.
    results = [_validate_request(request, now) for request in requests]
    return {"results": results, "accepted": sum(results), "problems": problems}

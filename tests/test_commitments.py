"""Tests for the optional snapshot_commitments envelope on IXFR replay.

When supplied, each change is bracketed by publisher-computed SHA-256 promises
over the *same* canonical record sequence the success response digests:
``before`` is checked as the change starts and ``after`` once every delete/add
rule has passed on the private candidate.
"""

from __future__ import annotations

import pytest

from app.engine import (
    ReplayError,
    _add,
    normalize_record,
    replay,
    snapshot_digest,
)

from .conftest import change, rr, soa


def _start():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
    ]


def _changes():
    return [
        change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")]),
        change(
            101,
            102,
            deletes=[rr("ns1.example.com", "A", address="192.0.2.10")],
            adds=[rr("ns1.example.com", "A", address="192.0.2.11")],
        ),
        change(102, 103),
    ]


def _zone_digest(records):
    """Digest of a valid record list, using the engine's canonical sequence."""
    zone: dict = {}
    for index, raw in enumerate(records):
        _add(zone, normalize_record(raw, 0, index), 0, index)
    return snapshot_digest(zone)


def _state_digests(start, changes):
    """Canonical digest before change 1 and after every change."""
    states = [_zone_digest(start)]
    for prefix in range(1, len(changes) + 1):
        states.append(
            replay({"start": start, "changes": changes[:prefix]})["sha256"]
        )
    return states


def _commitments(states):
    return [
        {"before_sha256": states[i], "after_sha256": states[i + 1]}
        for i in range(len(states) - 1)
    ]


def _payload(commitments=None, *, start=None, changes=None):
    start = start if start is not None else _start()
    changes = changes if changes is not None else _changes()
    payload = {"start": start, "changes": changes}
    if commitments is not None:
        payload["snapshot_commitments"] = commitments
    return payload


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_matching_commitments_succeed_and_are_marked():
    start, changes = _start(), _changes()
    commitments = _commitments(_state_digests(start, changes))

    result = replay(_payload(commitments))
    legacy = replay(_payload())

    assert result["sha256"] == legacy["sha256"]
    assert result["records"] == legacy["records"]
    assert result["final_serial"] == legacy["final_serial"] == 103
    assert result["snapshot_commitments_verified"] is True


def test_omitted_commitments_leave_response_untouched():
    result = replay(_payload())
    assert "snapshot_commitments_verified" not in result


def test_single_change_matching_commitment():
    start, changes = _start(), _changes()[:1]
    commitments = _commitments(_state_digests(start, changes))
    result = replay(_payload(commitments, start=start, changes=changes))
    assert result["snapshot_commitments_verified"] is True
    assert result["changes_applied"] == 1


# ---------------------------------------------------------------------------
# Envelope / format validation
# ---------------------------------------------------------------------------


def test_commitments_count_too_few():
    states = _state_digests(_start(), _changes())
    commitments = _commitments(states)[:-1]
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments))
    assert exc.value.code == "REQUEST_MALFORMED"
    assert exc.value.field == "snapshot_commitments"


def test_commitments_count_too_many():
    states = _state_digests(_start(), _changes())
    commitments = _commitments(states)
    commitments.append(dict(commitments[-1]))
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments))
    assert exc.value.code == "REQUEST_MALFORMED"


def test_commitments_not_an_array():
    with pytest.raises(ReplayError) as exc:
        replay(_payload({"before_sha256": "0" * 64, "after_sha256": "0" * 64}))
    assert exc.value.code == "REQUEST_MALFORMED"


def test_commitment_entry_must_be_object():
    commitments = [["nope"]]
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=_start(), changes=_changes()[:1]))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_INVALID"
    assert exc.value.change == 1


@pytest.mark.parametrize(
    "field_name,value",
    [
        ("before_sha256", "0" * 63),                  # too short
        ("before_sha256", "0" * 65),                  # too long
        ("before_sha256", "A" * 64),                  # uppercase hex
        ("before_sha256", "g" * 64),                  # not hex
        ("before_sha256", 123),                        # not a string
        ("before_sha256", None),                       # missing/null
        ("after_sha256", "0" * 63),
        ("after_sha256", "F" * 64),
        ("after_sha256", 456),
        ("after_sha256", None),
    ],
)
def test_commitment_digest_format(field_name, value):
    good = "0" * 64
    entry = {"before_sha256": good, "after_sha256": good}
    entry[field_name] = value
    with pytest.raises(ReplayError) as exc:
        replay(_payload([entry], start=_start(), changes=_changes()[:1]))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_INVALID"
    assert exc.value.change == 1
    assert exc.value.field == field_name


def test_missing_commitment_keys():
    with pytest.raises(ReplayError) as exc:
        replay(
            _payload(
                [{"before_sha256": "0" * 64}],
                start=_start(),
                changes=_changes()[:1],
            )
        )
    assert exc.value.code == "SNAPSHOT_COMMITMENT_INVALID"
    assert exc.value.field == "after_sha256"


def test_format_error_is_located_to_the_change():
    start, changes = _start(), _changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[1]["after_sha256"] = commitments[1]["after_sha256"].upper()
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=changes))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_INVALID"
    assert exc.value.change == 2


# ---------------------------------------------------------------------------
# Mismatch location, staging and non-disclosure
# ---------------------------------------------------------------------------


def test_before_mismatch_first_change():
    commitments = _commitments(_state_digests(_start(), _changes()))
    commitments[0]["before_sha256"] = "0" * 64
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 1
    assert exc.value.stage == "before"


def test_after_mismatch_is_located_and_staged():
    start, changes = _start(), _changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[1]["after_sha256"] = "f" * 64
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=changes))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 2
    assert exc.value.stage == "after"


def test_before_mismatch_later_change_runs_after_earlier_changes_apply():
    start, changes = _start(), _changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[2]["before_sha256"] = commitments[1]["before_sha256"]
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=changes))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 3
    assert exc.value.stage == "before"


def test_mismatch_payload_never_discloses_records_or_digests():
    start, changes = _start(), _changes()
    commitments = _commitments(_state_digests(start, changes))
    actual_after = commitments[0]["after_sha256"]
    commitments[0]["after_sha256"] = "f" * 64
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=changes))
    payload = exc.value.to_payload()
    assert set(payload) == {"code", "rule", "change", "message", "stage"}
    assert payload["stage"] == "after"
    assert actual_after not in str(payload)
    assert "192.0.2.20" not in str(payload)


def test_existing_rule_failure_takes_precedence_over_after_commitment():
    # Change 2 fails serial arithmetic; its after promise must never be checked,
    # so a bogus after digest must not mask the underlying rule error.
    start = _start()
    bad_changes = [
        change(100, 101),
        change(101, 101),  # serial not advanced
    ]
    states = _state_digests(start, bad_changes[:1])
    commitments = _commitments(states)
    commitments.append(
        {"before_sha256": states[-1], "after_sha256": "f" * 64}
    )
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=bad_changes))
    assert exc.value.code == "SERIAL_NOT_ADVANCED"
    assert exc.value.change == 2


def test_before_commitment_checked_before_change_rules():
    # An empty change (rejected by change_must_delete_and_add) still reports the
    # before mismatch first: the snapshot is pinned before any change rule runs.
    start = _start()
    changes = [{"deletes": [], "adds": []}]
    commitments = [{"before_sha256": "f" * 64, "after_sha256": "0" * 64}]
    with pytest.raises(ReplayError) as exc:
        replay(_payload(commitments, start=start, changes=changes))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.stage == "before"


def test_commitments_use_success_response_digest_scheme():
    # The promise for the final state must equal the success sha256 exactly.
    start, changes = _start(), _changes()
    states = _state_digests(start, changes)
    commitments = _commitments(states)
    result = replay(_payload(commitments, start=start, changes=changes))
    assert commitments[-1]["after_sha256"] == result["sha256"]
    assert commitments[0]["before_sha256"] == _zone_digest(start)

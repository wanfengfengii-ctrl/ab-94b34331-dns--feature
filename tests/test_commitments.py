"""Tests for optional per-change snapshot commitments.

The publisher of an incremental log may pin the canonical zone snapshot it
saw before/after every change. The replay engine must then verify both sides
agree on the canonical state, reject count/format/digest problems with a
stable code + change + phase (never leaking candidate records or digests),
and explicitly mark fully verified responses.
"""

from __future__ import annotations

import json

import pytest

from fastapi.testclient import TestClient

from app.api import app
from app.engine import RRset, ReplayError, normalize_record, replay, snapshot_digest

from .conftest import change, rr, soa

client = TestClient(app)


def _start():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
    ]


def _changes():
    return [
        change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")]),
        change(101, 102, deletes=[rr("ns1.example.com", "A", 300, address="192.0.2.10")]),
    ]


def _payload(**extra):
    body = {"start": _start(), "changes": _changes()}
    body.update(extra)
    return body


def digest_of(records):
    """Canonical digest of a bare record list, via the engine's own rules."""
    zone = {}
    for index, raw in enumerate(records):
        record = normalize_record(raw, 0, index)
        key = (record.name, record.rtype)
        rrset = zone.get(key)
        if rrset is None:
            zone[key] = RRset(ttl=record.ttl, rdatas={record.rdata})
        else:
            rrset.rdatas.add(record.rdata)
    return snapshot_digest(zone)


def commitments_for(start, changes):
    """Derive the correct before/after pair for every change in order."""
    before = digest_of(start)
    pairs = []
    for count in range(1, len(changes) + 1):
        after = replay({"start": start, "changes": changes[:count]})["sha256"]
        pairs.append({"before_sha256": before, "after_sha256": after})
        before = after
    return pairs


def good_commitments():
    return commitments_for(_start(), _changes())


def tamper(digest: str) -> str:
    """Flip one hex character, keeping a valid lowercase-hex shape."""
    return ("0" if digest[0] != "0" else "1") + digest[1:]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_matching_commitments_are_verified_and_snapshot_unchanged():
    body = _payload()
    baseline = replay(body)
    committed = replay({**body, "snapshot_commitments": good_commitments()})
    assert committed["commitments_verified"] is True
    # The final snapshot itself is exactly what an uncommitted replay returns.
    assert committed["sha256"] == baseline["sha256"]
    assert committed["records"] == baseline["records"]
    assert committed["final_serial"] == baseline["final_serial"]


def test_omitted_commitments_leave_response_unchanged():
    result = replay(_payload())
    assert "commitments_verified" not in result


def test_null_commitments_are_treated_as_omitted():
    result = replay(_payload(snapshot_commitments=None))
    assert "commitments_verified" not in result
    assert result["final_serial"] == 102


def test_single_change_commitment_against_start_zone():
    start = _start()
    changes = _changes()[:1]
    pairs = commitments_for(start, changes)
    assert pairs[0]["before_sha256"] == digest_of(start)
    result = replay({"start": start, "changes": changes, "snapshot_commitments": pairs})
    assert result["commitments_verified"] is True
    assert result["sha256"] == pairs[0]["after_sha256"]


# ---------------------------------------------------------------------------
# Envelope: count and format
# ---------------------------------------------------------------------------


def test_commitment_count_must_match_changes():
    pairs = good_commitments()
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs[:1]))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"
    assert exc.value.change == 0
    assert exc.value.phase == "before"

    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs + [pairs[0]]))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"


@pytest.mark.parametrize("raw", [{"before_sha256": "x"}, "not-a-list", 42])
def test_commitments_must_be_an_array(raw):
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=raw))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"
    assert exc.value.change == 0
    assert exc.value.phase == "before"


def test_commitment_element_must_be_an_object():
    pairs = good_commitments()
    pairs[1] = "junk"
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"
    assert exc.value.change == 2
    assert exc.value.phase == "before"


@pytest.mark.parametrize(
    "bad_value",
    [
        "A" * 64,          # uppercase hex is not lowercase hex
        "g" * 64,          # not hex at all
        "ab12",            # too short
        "a" * 63,
        "a" * 65,
        1234,              # not a string
        None,              # missing/null
    ],
)
def test_commitment_digests_must_be_lowercase_hex_sha256(bad_value):
    pairs = good_commitments()
    pairs[0]["before_sha256"] = bad_value
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"
    assert exc.value.change == 1
    assert exc.value.phase == "before"
    assert exc.value.field == "before_sha256"


def test_after_digest_format_locates_after_phase():
    pairs = good_commitments()
    pairs[1]["after_sha256"] = "ZZ" + pairs[1]["after_sha256"][2:]
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "INVALID_SNAPSHOT_COMMITMENT"
    assert exc.value.change == 2
    assert exc.value.phase == "after"
    assert exc.value.field == "after_sha256"


# ---------------------------------------------------------------------------
# Digest mismatches
# ---------------------------------------------------------------------------


def test_before_digest_mismatch_locates_change_and_phase():
    pairs = good_commitments()
    pairs[1]["before_sha256"] = tamper(pairs[1]["before_sha256"])
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 2
    assert exc.value.phase == "before"


def test_after_digest_mismatch_locates_change_and_phase():
    pairs = good_commitments()
    pairs[0]["after_sha256"] = tamper(pairs[0]["after_sha256"])
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 1
    assert exc.value.phase == "after"


def test_wrong_baseline_caught_on_first_change():
    pairs = good_commitments()
    pairs[0]["before_sha256"] = tamper(pairs[0]["before_sha256"])
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 1
    assert exc.value.phase == "before"


def test_before_check_runs_before_change_rules():
    """A tampered before-commitment wins over an independently broken change."""
    pairs = good_commitments()
    pairs[1]["before_sha256"] = tamper(pairs[1]["before_sha256"])
    changes = _changes()
    changes[1] = change(101, 101)  # serial not advancing: would fail anyway
    with pytest.raises(ReplayError) as exc:
        replay(
            {
                "start": _start(),
                "changes": changes,
                "snapshot_commitments": pairs,
            }
        )
    assert exc.value.code == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert exc.value.change == 2
    assert exc.value.phase == "before"


@pytest.mark.parametrize("phase", ["before", "after"])
def test_mismatch_error_carries_no_candidate_records_or_digests(phase):
    pairs = good_commitments()
    key = f"{phase}_sha256"
    leaked = tamper(pairs[1][key])
    pairs[1][key] = leaked
    with pytest.raises(ReplayError) as exc:
        replay(_payload(snapshot_commitments=pairs))
    payload = exc.value.to_payload()
    assert payload["code"] == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert payload["change"] == 2
    assert payload["phase"] == phase
    # No candidate snapshot, no expected/actual digest anywhere in the error.
    assert "records" not in payload
    assert "sha256" not in payload
    serialized = json.dumps(payload)
    assert leaked not in serialized
    assert good_commitments()[1][key] not in serialized


# ---------------------------------------------------------------------------
# HTTP level
# ---------------------------------------------------------------------------


def test_api_committed_replay_marks_verified():
    response = client.post(
        "/api/dns/ixfr/replay",
        json=_payload(snapshot_commitments=good_commitments()),
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["commitments_verified"] is True
    assert data["final_serial"] == 102
    assert len(data["sha256"]) == 64


def test_api_legacy_request_response_unchanged():
    response = client.post("/api/dns/ixfr/replay", json=_payload())
    assert response.status_code == 200
    data = response.json()
    assert "commitments_verified" not in data
    assert set(data.keys()) == {
        "apex",
        "final_serial",
        "changes_applied",
        "records",
        "sha256",
    }


def test_api_commitment_count_mismatch_is_422_with_change_and_phase():
    response = client.post(
        "/api/dns/ixfr/replay",
        json=_payload(snapshot_commitments=good_commitments()[:1]),
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "INVALID_SNAPSHOT_COMMITMENT"
    assert error["change"] == 0
    assert error["phase"] == "before"
    assert set(response.json().keys()) == {"error"}


def test_api_before_mismatch_is_422_without_candidate_data():
    pairs = good_commitments()
    leaked = tamper(pairs[1]["before_sha256"])
    pairs[1]["before_sha256"] = leaked
    response = client.post(
        "/api/dns/ixfr/replay", json=_payload(snapshot_commitments=pairs)
    )
    assert response.status_code == 422
    body = response.json()
    error = body["error"]
    assert error["code"] == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert error["change"] == 2
    assert error["phase"] == "before"
    # Neither a partial snapshot nor any digest leaks into the error body.
    assert set(body.keys()) == {"error"}
    assert "records" not in body
    assert leaked not in json.dumps(body)


def test_api_after_mismatch_is_422_without_candidate_data():
    pairs = good_commitments()
    leaked = tamper(pairs[0]["after_sha256"])
    pairs[0]["after_sha256"] = leaked
    response = client.post(
        "/api/dns/ixfr/replay", json=_payload(snapshot_commitments=pairs)
    )
    assert response.status_code == 422
    body = response.json()
    error = body["error"]
    assert error["code"] == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert error["change"] == 1
    assert error["phase"] == "after"
    assert set(body.keys()) == {"error"}
    assert leaked not in json.dumps(body)

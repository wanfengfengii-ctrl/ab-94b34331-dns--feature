"""HTTP-level tests for POST /api/dns/ixfr/replay, including wraparound."""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app.api import app
from app.engine import SERIAL_MOD

from .conftest import change, rr, soa

client = TestClient(app)


def _start():
    return [
        soa(SERIAL_MOD - 2),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
    ]


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_replay_success_envelope():
    body = {
        "start": _start(),
        "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 1)],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200
    data = response.json()
    assert data["final_serial"] == SERIAL_MOD - 1
    assert data["apex"] == "example.com"
    assert len(data["sha256"]) == 64
    # canonical, stable ordering
    keys = [(r["name"], r["type"]) for r in data["records"]]
    assert keys == sorted(keys, key=lambda k: (k[0], {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}[k[1]]))


def test_api_serial_wraparound_smoke():
    """End-to-end wraparound: 2^32-2 -> 2^32-1 -> 0 -> 1."""
    body = {
        "start": _start(),
        "changes": [
            change(SERIAL_MOD - 2, SERIAL_MOD - 1),
            change(SERIAL_MOD - 1, 0),
            change(0, 1),
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["final_serial"] == 1
    assert data["changes_applied"] == 3


def test_api_error_locates_change_and_rule():
    body = {
        "start": _start(),
        "changes": [
            change(SERIAL_MOD - 2, SERIAL_MOD - 1),
            change(SERIAL_MOD - 1, SERIAL_MOD - 1),  # equal serial
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SERIAL_NOT_ADVANCED"
    assert error["rule"] == "serial_must_advance_per_rfc1982"
    assert error["change"] == 2
    assert "records" not in response.json()


def test_api_missing_delete_is_422_with_change_and_record():
    body = {
        "start": _start(),
        "changes": [
            change(
                SERIAL_MOD - 2,
                SERIAL_MOD - 1,
                deletes=[rr("nope.example.com", "A", address="192.0.2.55")],
            )
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "DELETE_NOT_FOUND"
    assert error["change"] == 1
    assert error["record"] == 1


def test_api_cname_conflict():
    body = {
        "start": _start(),
        "changes": [
            {
                "deletes": [soa(SERIAL_MOD - 2)],
                "adds": [
                    rr("www.example.com", "A", address="192.0.2.80"),
                    soa(SERIAL_MOD - 1),
                ],
            }
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CNAME_CONFLICT"


def test_malformed_json_body():
    response = client.post(
        "/api/dns/ixfr/replay",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_MALFORMED"


def test_no_partial_snapshot_field_on_failure():
    # serial moves backwards across the 32-bit boundary -> rejected
    body = {"start": _start(), "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 3)]}
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert set(response.json().keys()) == {"error"}


@pytest.mark.parametrize(
    "record",
    [
        {"name": "x.example.com", "type": "A", "ttl": 300, "address": "999.1.1.1"},
        {"name": "x.example.com", "type": "AAAA", "ttl": 300, "address": "nope"},
        {"name": "x.example.com", "type": "SOA", "ttl": 300},
        {"name": "bad name.example.com", "type": "A", "ttl": 300, "address": "1.2.3.4"},
        {"name": "x.example.com", "type": "MX", "ttl": 300},
        {"name": "x.example.com", "type": "A", "ttl": -1, "address": "1.2.3.4"},
    ],
)
def test_invalid_record_shapes(record):
    body = {
        "start": [soa(SERIAL_MOD - 2), record],
        "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 1)],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_RECORD"


# ---------------------------------------------------------------------------
# snapshot_commitments
# ---------------------------------------------------------------------------


def _state_digests(start, changes):
    """Canonical digest of the start zone and after each change prefix."""
    from app.engine import _add, normalize_record, snapshot_digest

    zone: dict = {}
    for index, raw in enumerate(start):
        _add(zone, normalize_record(raw, 0, index), 0, index)
    digests = [snapshot_digest(zone)]
    for prefix in range(1, len(changes) + 1):
        response = client.post(
            "/api/dns/ixfr/replay",
            json={"start": start, "changes": changes[:prefix]},
        )
        assert response.status_code == 200, response.text
        digests.append(response.json()["sha256"])
    return digests


def _commitments(digests):
    return [
        {"before_sha256": digests[i], "after_sha256": digests[i + 1]}
        for i in range(len(digests) - 1)
    ]


def _committed_changes():
    return [
        change(SERIAL_MOD - 2, SERIAL_MOD - 1, adds=[rr("mail.example.com", "A", address="192.0.2.20")]),
        change(SERIAL_MOD - 1, 0),
        change(0, 1),
    ]


def test_committed_replay_success_is_marked_and_unchanged_otherwise():
    start, changes = _start(), _committed_changes()
    commitments = _commitments(_state_digests(start, changes))

    committed = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    legacy = client.post(
        "/api/dns/ixfr/replay", json={"start": start, "changes": changes}
    )
    assert committed.status_code == 200, committed.text
    cdata, ldata = committed.json(), legacy.json()
    assert cdata["snapshot_commitments_verified"] is True
    assert "snapshot_commitments_verified" not in ldata
    for key in ("apex", "final_serial", "changes_applied", "records", "sha256"):
        assert cdata[key] == ldata[key]


def test_commitments_count_mismatch_is_422():
    start, changes = _start(), _committed_changes()
    commitments = _commitments(_state_digests(start, changes))[:-1]
    response = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "REQUEST_MALFORMED"


def test_commitment_uppercase_digest_rejected_with_change_and_field():
    start, changes = _start(), _committed_changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[1]["after_sha256"] = commitments[1]["after_sha256"].upper()
    response = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SNAPSHOT_COMMITMENT_INVALID"
    assert error["change"] == 2
    assert error["field"] == "after_sha256"


def test_before_commitment_mismatch_locates_change_and_stage():
    start, changes = _start(), _committed_changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[0]["before_sha256"] = "0" * 64
    response = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert error["change"] == 1
    assert error["stage"] == "before"


def test_after_commitment_mismatch_locates_change_and_stage():
    start, changes = _start(), _committed_changes()
    commitments = _commitments(_state_digests(start, changes))
    commitments[2]["after_sha256"] = "f" * 64
    response = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SNAPSHOT_COMMITMENT_MISMATCH"
    assert error["change"] == 3
    assert error["stage"] == "after"


def test_commitment_mismatch_never_leaks_records_or_digests():
    start, changes = _start(), _committed_changes()
    digests = _state_digests(start, changes)
    commitments = _commitments(digests)
    real_before = commitments[0]["before_sha256"]
    commitments[0]["before_sha256"] = "0" * 64
    response = client.post(
        "/api/dns/ixfr/replay",
        json={"start": start, "changes": changes, "snapshot_commitments": commitments},
    )
    assert response.status_code == 422
    raw = response.text
    assert "records" not in response.json()
    assert "sha256" not in response.json().get("error", {})
    assert real_before not in raw
    assert "192.0.2.20" not in raw

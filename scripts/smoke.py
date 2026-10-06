#!/usr/bin/env python3
"""One-shot API smoke test used by the Compose ``verify`` service.

It exercises the running API over HTTP only:

1. health endpoint,
2. a successful replay that crosses the 32-bit serial boundary (wraparound),
3. deterministic digest and canonical ordering,
4. an illegal log that must be rejected with a stable, change-located error
   code and must never leak a partial snapshot,
5. publisher snapshot commitments: a fully pinned replay must verify and be
   marked as such, while tampered/malformed commitments must be rejected
   with a stable code, the change number, and the phase — again without
   leaking candidate records or digests.

Exits 0 only when every assertion holds.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
WRAP = 1 << 32


def soa(serial: int) -> dict:
    return {
        "name": "example.com",
        "type": "SOA",
        "ttl": 3600,
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
        "serial": serial % WRAP,
        "refresh": 7200,
        "retry": 3600,
        "expire": 1209600,
        "minimum": 60,
    }


def a(name: str, address: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "A", "ttl": ttl, "address": address}


def change(serial_from: int, serial_to: int, deletes=None, adds=None) -> dict:
    return {
        "deletes": [soa(serial_from), *(deletes or [])],
        "adds": [*(adds or []), soa(serial_to)],
    }


def request(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def check(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        print(f"FAIL: {label} {detail}".rstrip())
        sys.exit(1)
    print(f"PASS: {label}")


TYPE_RANK = {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}


def rdata_tokens(record: dict) -> list:
    if record["type"] == "SOA":
        return [
            str(record[key])
            for key in ("mname", "rname", "serial", "refresh", "retry", "expire", "minimum")
        ]
    if record["type"] in ("A", "AAAA"):
        return [record["address"]]
    if record["type"] == "CNAME":
        return [record["target"]]
    return [record["text"]]


def canonical_digest(records: list) -> str:
    """SHA-256 over the same canonical record sequence the API publishes."""
    ordered = sorted(
        records, key=lambda r: (r["name"], TYPE_RANK[r["type"]], rdata_tokens(r))
    )
    lines = [
        " ".join([r["name"], r["type"], str(r["ttl"]), *rdata_tokens(r)])
        for r in ordered
    ]
    return hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()


def tamper_hex(digest: str) -> str:
    """Flip one hex character, keeping a valid lowercase-hex shape."""
    return ("0" if digest[0] != "0" else "1") + digest[1:]


def main() -> int:
    status, body = request("GET", "/healthz")
    check("healthz returns 200", status == 200 and body.get("status") == "ok")

    start = [
        soa(WRAP - 2),
        a("example.com", "192.0.2.1"),
        a("ns1.example.com", "192.0.2.10"),
    ]

    # --- Successful replay crossing the serial boundary ---------------------
    payload = {
        "start": start,
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("mail.example.com", "192.0.2.20")]),
            change(WRAP - 1, 0),
            change(0, 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", payload)
    check("wraparound replay returns 200", status == 200, str(body))
    check("final serial wrapped to 1", body.get("final_serial") == 1, str(body.get("final_serial")))
    check("all three changes applied", body.get("changes_applied") == 3)
    digest = body.get("sha256", "")
    check("sha256 digest present", len(digest) == 64 and all(c in "0123456789abcdef" for c in digest))

    records = body.get("records", [])
    keys = [(r["name"], r["type"]) for r in records]
    type_rank = {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}
    check("records are canonically sorted", keys == sorted(keys, key=lambda k: (k[0], type_rank[k[1]])))
    check("soa is at apex only", all(
        not (r["type"] == "SOA" and r["name"] != "example.com") for r in records
    ))
    check("added record visible", any(
        r["name"] == "mail.example.com" and r.get("address") == "192.0.2.20" for r in records
    ))

    # Replaying the identical payload yields the identical digest.
    status, body2 = request("POST", "/api/dns/ixfr/replay", payload)
    check("digest is deterministic", status == 200 and body2.get("sha256") == digest)
    check("legacy response carries no verification marker",
          "commitments_verified" not in body2, str(body2.keys()))

    # --- Snapshot commitments: publisher-pinned before/after digests --------
    # after[i] is the digest the API itself reports for the first i+1 changes;
    # before[0] is the locally computed canonical digest of the start zone.
    afters = []
    for count in range(1, len(payload["changes"]) + 1):
        status, prefix = request(
            "POST", "/api/dns/ixfr/replay",
            {"start": start, "changes": payload["changes"][:count]},
        )
        check(f"prefix replay of {count} change(s) returns 200", status == 200, str(prefix))
        afters.append(prefix.get("sha256", ""))
    befores = [canonical_digest(start)] + afters[:-1]
    commitments = [
        {"before_sha256": before, "after_sha256": after}
        for before, after in zip(befores, afters)
    ]

    status, body = request(
        "POST", "/api/dns/ixfr/replay",
        dict(payload, snapshot_commitments=commitments),
    )
    check("committed replay returns 200", status == 200, str(body))
    check("commitments explicitly verified",
          body.get("commitments_verified") is True, str(body.get("commitments_verified")))
    check("committed snapshot identical to legacy replay", body.get("sha256") == digest)

    # Tampered after-digest on change 2: stable code, change, phase, no leak.
    tampered = [dict(pair) for pair in commitments]
    tampered[1]["after_sha256"] = tamper_hex(tampered[1]["after_sha256"])
    status, body = request(
        "POST", "/api/dns/ixfr/replay",
        dict(payload, snapshot_commitments=tampered),
    )
    check("tampered after-commitment rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("stable mismatch code",
          error.get("code") == "SNAPSHOT_COMMITMENT_MISMATCH", str(error))
    check("mismatch locates change 2", error.get("change") == 2, str(error))
    check("mismatch names the after phase", error.get("phase") == "after", str(error))
    leaked = json.dumps(body)
    check("no candidate snapshot or digest leaked",
          set(body.keys()) == {"error"}
          and tampered[1]["after_sha256"] not in leaked
          and afters[1] not in leaked, str(body))

    # Tampered before-digest on change 1 (wrong baseline).
    tampered = [dict(pair) for pair in commitments]
    tampered[0]["before_sha256"] = tamper_hex(tampered[0]["before_sha256"])
    status, body = request(
        "POST", "/api/dns/ixfr/replay",
        dict(payload, snapshot_commitments=tampered),
    )
    error = body.get("error", {})
    check("tampered before-commitment rejected",
          status == 422 and error.get("code") == "SNAPSHOT_COMMITMENT_MISMATCH", str(body))
    check("before-mismatch locates change 1 and before phase",
          error.get("change") == 1 and error.get("phase") == "before", str(error))

    # Commitment count must equal the number of changes.
    status, body = request(
        "POST", "/api/dns/ixfr/replay",
        dict(payload, snapshot_commitments=commitments[:-1]),
    )
    error = body.get("error", {})
    check("short commitment list rejected",
          status == 422 and error.get("code") == "INVALID_SNAPSHOT_COMMITMENT", str(body))
    check("count error carries change and phase",
          "change" in error and "phase" in error, str(error))

    # Digests must be lowercase hex.
    malformed = [dict(pair) for pair in commitments]
    malformed[0]["before_sha256"] = malformed[0]["before_sha256"].upper()
    status, body = request(
        "POST", "/api/dns/ixfr/replay",
        dict(payload, snapshot_commitments=malformed),
    )
    error = body.get("error", {})
    check("uppercase digest rejected",
          status == 422 and error.get("code") == "INVALID_SNAPSHOT_COMMITMENT", str(body))
    check("format error locates change 1 and before phase",
          error.get("change") == 1 and error.get("phase") == "before", str(error))

    # --- Illegal log: serial does not advance in change 2 -------------------
    bad = {
        "start": [soa(WRAP - 2), a("example.com", "192.0.2.1")],
        "changes": [
            change(WRAP - 2, WRAP - 1),
            change(WRAP - 1, WRAP - 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad)
    check("illegal log rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("stable error code", error.get("code") == "SERIAL_NOT_ADVANCED", str(error))
    check("error locates the change (2)", error.get("change") == 2, str(error))
    check("error names the violated rule", bool(error.get("rule")))
    check("no partial snapshot leaked", set(body.keys()) == {"error"}, str(body.keys()))

    # --- Illegal log: delete misses an existing record ----------------------
    bad_delete = {
        "start": [soa(WRAP - 2)],
        "changes": [change(WRAP - 2, WRAP - 1, deletes=[a("ghost.example.com", "192.0.2.66")])],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad_delete)
    error = body.get("error", {})
    check("missing delete rejected", status == 422 and error.get("code") == "DELETE_NOT_FOUND", str(body))
    check("missing delete located to record 1", error.get("record") == 1)

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

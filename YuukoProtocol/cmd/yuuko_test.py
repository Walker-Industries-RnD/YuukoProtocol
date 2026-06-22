#!/usr/bin/env python3
"""
yuuko_test.py — YuukoProtocol v1.1 CMD Test Harness
Walker Industries R&D

Tests ALL protocol behaviors:
  • Publish / Subscribe / Request / Tombstone
  • Named topic labels (VectorGearStreetpass, XRUIOSStreetpass, etc.)
  • All PayloadType variants
  • All YuukoFlags
  • Ephemeral (not stored) packets
  • Tombstone (delete signals)
  • Multi-subscriber fan-out
  • LocalBroker (offline) and EclipseBroker (if server running)

Usage:
  python yuuko_test.py            # runs all tests (LocalBroker only)
  python yuuko_test.py --eclipse  # also runs Eclipse server tests
  python yuuko_test.py --topic VectorGearStreetpass  # single topic smoke test
"""

import sys
import os
import asyncio
import argparse
import textwrap
import time

# ── path bootstrap ────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from yuuko_bridge import (
    YuukoPacket, PayloadType, YuukoTopics, YuukoFlags,
    LocalBroker, EclipseClient
)

# ── ANSI colours ──────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
DIM    = "\033[2m"

def _pass(msg): print(f"  {GREEN}✓{RESET}  {msg}")
def _fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def _info(msg): print(f"  {CYAN}·{RESET}  {msg}")
def _warn(msg): print(f"  {YELLOW}!{RESET}  {msg}")
def _head(msg): print(f"\n{BOLD}{PURPLE}── {msg} {RESET}")
def _sep():     print(f"  {DIM}{'─'*60}{RESET}")


# ── Test results tracker ──────────────────────────────────────────────────────

class TestResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def ok(self, label):
        self.passed += 1
        _pass(label)

    def fail(self, label, reason=""):
        self.failed += 1
        _fail(f"{label}{f'  →  {reason}' if reason else ''}")

    def skip(self, label):
        self.skipped += 1
        _warn(f"SKIP  {label}")

    def assert_true(self, cond, label, reason=""):
        if cond:
            self.ok(label)
        else:
            self.fail(label, reason)

    def summary(self):
        total = self.passed + self.failed + self.skipped
        colour = GREEN if self.failed == 0 else RED
        print(f"\n{BOLD}{'─'*64}{RESET}")
        print(f"  Results  {colour}{self.passed} passed{RESET}  "
              f"{RED if self.failed else DIM}{self.failed} failed{RESET}  "
              f"{DIM}{self.skipped} skipped{RESET}  /  {total} total")
        print(f"{BOLD}{'─'*64}{RESET}\n")
        return self.failed == 0


r = TestResults()


# ═════════════════════════════════════════════════════════════════════════════
#  TEST SUITES
# ═════════════════════════════════════════════════════════════════════════════

# ── 1. Topic label constants ──────────────────────────────────────────────────

async def test_topic_labels():
    _head("Topic Label Constants")

    pairs = [
        ("VectorGearStreetpass",  YuukoTopics.VECTOR_GEAR_STREETPASS,  "yuuko/streetpass/vectorgear"),
        ("XRUIOSStreetpass",       YuukoTopics.XRUIOS_STREETPASS,        "yuuko/streetpass/xruios"),
        ("GatewayStreetpass",      YuukoTopics.GATEWAY_STREETPASS,       "yuuko/streetpass/gateway"),
        ("BindingsDirectories",    YuukoTopics.BINDINGS_DIRECTORIES,     "yuuko/bindings/directories"),
        ("BindingsFiles",          YuukoTopics.BINDINGS_FILES,           "yuuko/bindings/files"),
        ("VectorGearSensors",      YuukoTopics.VECTOR_GEAR_SENSORS,      "yuuko/vectorgear/sensors"),
        ("VectorGearTracking",     YuukoTopics.VECTOR_GEAR_TRACKING,     "yuuko/vectorgear/tracking"),
        ("VectorGearStatus",       YuukoTopics.VECTOR_GEAR_STATUS,       "yuuko/vectorgear/status"),
        ("XRUIOSConfig",           YuukoTopics.XRUIOS_CONFIG,            "yuuko/xruios/config"),
        ("XRUIOSEvents",           YuukoTopics.XRUIOS_EVENTS,            "yuuko/xruios/events"),
        ("XRUIOSSync",             YuukoTopics.XRUIOS_SYNC,              "yuuko/xruios/sync"),
        ("GatewayMesh",            YuukoTopics.GATEWAY_MESH,             "yuuko/gateway/mesh"),
        ("GatewayPeers",           YuukoTopics.GATEWAY_PEERS,            "yuuko/gateway/peers"),
        ("ShinraEyeTracking",      YuukoTopics.SHINRA_EYE_TRACKING,      "yuuko/shinra/eye"),
        ("ShinraFaceTracking",     YuukoTopics.SHINRA_FACE_TRACKING,     "yuuko/shinra/face"),
        ("SystemHeartbeat",        YuukoTopics.SYSTEM_HEARTBEAT,         "yuuko/system/heartbeat"),
        ("SystemDiagnostics",      YuukoTopics.SYSTEM_DIAGNOSTICS,       "yuuko/system/diagnostics"),
    ]

    for label, actual, expected in pairs:
        r.assert_true(actual == expected, f"YuukoTopics.{label} = {expected!r}",
                      f"got {actual!r}")


# ── 2. Packet construction ────────────────────────────────────────────────────

async def test_packet_construction():
    _head("Packet Construction & Flags")

    # Basic
    pkt = YuukoPacket(name="test", type=PayloadType.BYTES, data=b"\x01\x02\x03")
    r.assert_true(pkt.name == "test",             "name stored correctly")
    r.assert_true(pkt.type == PayloadType.BYTES,  "type stored correctly")
    r.assert_true(pkt.data == b"\x01\x02\x03",   "data stored correctly")
    r.assert_true(pkt.flags == [],                "default flags empty")

    # Tombstone flag
    tomb = YuukoPacket(name="dead", type=PayloadType.BYTES, data=b"",
                       flags=[YuukoFlags.TOMBSTONE])
    r.assert_true(tomb.is_tombstone(), "tombstone flag detected")
    r.assert_true(not tomb.is_ephemeral(), "tombstone != ephemeral")

    # Ephemeral flag
    ephem = YuukoPacket(name="fire", type=PayloadType.BYTES, data=b"boom",
                        flags=[YuukoFlags.EPHEMERAL])
    r.assert_true(ephem.is_ephemeral(), "ephemeral flag detected")

    # JSON type
    json_pkt = YuukoPacket(name="cfg", type=PayloadType.JSON,
                            data=b'{"sync":true}')
    r.assert_true(json_pkt.type == PayloadType.JSON, "JSON payload type")

    # All PayloadTypes round-trip
    for pt in PayloadType:
        pkt2 = YuukoPacket(name="x", type=pt, data=b"y")
        r.assert_true(pkt2.type == pt, f"PayloadType.{pt.value} round-trip")

    # to_dict / from_dict
    d = pkt.to_dict()
    pkt3 = YuukoPacket.from_dict(d)
    r.assert_true(pkt3.name == pkt.name and pkt3.data == pkt.data,
                  "to_dict/from_dict round-trip")


# ── 3. LocalBroker — publish / subscribe ────────────────────────────────────

async def test_local_pubsub():
    _head("LocalBroker — Publish / Subscribe")

    broker = LocalBroker()
    received: list[YuukoPacket] = []

    async def handler(pkt: YuukoPacket):
        received.append(pkt)

    await broker.subscribe(YuukoTopics.VECTOR_GEAR_STREETPASS, handler)

    pkt = YuukoPacket(name="vg-peer-001", type=PayloadType.JSON,
                       data=b'{"device":"VectorGear","rssi":-42}')
    await broker.publish(YuukoTopics.VECTOR_GEAR_STREETPASS, pkt)

    await asyncio.sleep(0.01)
    r.assert_true(len(received) == 1, "handler fired once")
    r.assert_true(received[0].name == "vg-peer-001", "correct packet received")


# ── 4. LocalBroker — request (pull) ──────────────────────────────────────────

async def test_local_request():
    _head("LocalBroker — Request (Pull)")

    broker = LocalBroker()

    # Publish three packets on XRUIOSStreetpass
    for i in range(3):
        pkt = YuukoPacket(name=f"xruios-peer-{i:03d}", type=PayloadType.JSON,
                           data=f'{{"id":{i}}}'.encode())
        await broker.publish(YuukoTopics.XRUIOS_STREETPASS, pkt)

    stored = await broker.request(YuukoTopics.XRUIOS_STREETPASS)
    r.assert_true(len(stored) == 3, "3 packets stored after publish")
    r.assert_true(stored[0].name == "xruios-peer-000", "first packet name correct")

    # Empty topic
    empty = await broker.request(YuukoTopics.GATEWAY_STREETPASS)
    r.assert_true(len(empty) == 0, "empty topic returns []")


# ── 5. Tombstone (delete signal) ─────────────────────────────────────────────

async def test_tombstone():
    _head("Tombstone (Delete Signal)")

    broker = LocalBroker()

    pkt = YuukoPacket(name="vg-peer-dead", type=PayloadType.BYTES, data=b"\xff")
    await broker.publish(YuukoTopics.VECTOR_GEAR_STREETPASS, pkt)
    stored = await broker.request(YuukoTopics.VECTOR_GEAR_STREETPASS)
    r.assert_true(len(stored) == 1, "packet stored before tombstone")

    await broker.tombstone(YuukoTopics.VECTOR_GEAR_STREETPASS, "vg-peer-dead")
    stored2 = await broker.request(YuukoTopics.VECTOR_GEAR_STREETPASS)
    r.assert_true(len(stored2) == 0, "packet removed after tombstone")


# ── 6. Ephemeral packets ──────────────────────────────────────────────────────

async def test_ephemeral():
    _head("Ephemeral Packets (Fire-and-Forget)")

    broker = LocalBroker()
    fired: list[YuukoPacket] = []

    async def handler(pkt):
        fired.append(pkt)

    await broker.subscribe(YuukoTopics.SYSTEM_HEARTBEAT, handler)

    ephem = YuukoPacket(name="hb-001", type=PayloadType.BYTES, data=b"ping",
                         flags=[YuukoFlags.EPHEMERAL])
    await broker.publish(YuukoTopics.SYSTEM_HEARTBEAT, ephem)
    await asyncio.sleep(0.01)

    r.assert_true(len(fired) == 1,  "ephemeral handler fired")
    stored = await broker.request(YuukoTopics.SYSTEM_HEARTBEAT)
    r.assert_true(len(stored) == 0, "ephemeral NOT stored")


# ── 7. Multi-subscriber fan-out ──────────────────────────────────────────────

async def test_fanout():
    _head("Multi-Subscriber Fan-out")

    broker = LocalBroker()
    buckets: list[list[YuukoPacket]] = [[], [], []]

    for i, bucket in enumerate(buckets):
        async def make_handler(b):
            async def h(pkt): b.append(pkt)
            return h
        await broker.subscribe(YuukoTopics.SHINRA_EYE_TRACKING, await make_handler(bucket))

    pkt = YuukoPacket(name="eye-frame-001", type=PayloadType.BYTE_ARRAY, data=b"\x00\x01")
    await broker.publish(YuukoTopics.SHINRA_EYE_TRACKING, pkt)
    await asyncio.sleep(0.02)

    for i, b in enumerate(buckets):
        r.assert_true(len(b) == 1, f"subscriber {i+1} received packet")


# ── 8. Unsubscribe ────────────────────────────────────────────────────────────

async def test_unsubscribe():
    _head("Unsubscribe")

    broker = LocalBroker()
    called = []

    async def handler(pkt): called.append(pkt)

    await broker.subscribe(YuukoTopics.GATEWAY_MESH, handler)
    await broker.publish(YuukoTopics.GATEWAY_MESH,
                          YuukoPacket(name="g1", type=PayloadType.BYTES, data=b"a"))
    await asyncio.sleep(0.01)
    r.assert_true(len(called) == 1, "handler fires before unsub")

    await broker.unsubscribe(YuukoTopics.GATEWAY_MESH, handler)
    await broker.publish(YuukoTopics.GATEWAY_MESH,
                          YuukoPacket(name="g2", type=PayloadType.BYTES, data=b"b"))
    await asyncio.sleep(0.01)
    r.assert_true(len(called) == 1, "handler NOT fired after unsub")


# ── 9. Packet deduplication (same name → overwrite) ──────────────────────────

async def test_dedup():
    _head("Packet Deduplication (name-keyed storage)")

    broker = LocalBroker()
    for i in range(5):
        pkt = YuukoPacket(name="status", type=PayloadType.JSON,
                           data=f'{{"seq":{i}}}'.encode())
        await broker.publish(YuukoTopics.VECTOR_GEAR_STATUS, pkt)

    stored = await broker.request(YuukoTopics.VECTOR_GEAR_STATUS)
    r.assert_true(len(stored) == 1,           "only 1 packet (latest) stored")
    r.assert_true(b'"seq":4' in stored[0].data, "latest value retained")


# ── 10. Binding sync flag ─────────────────────────────────────────────────────

async def test_binding_flags():
    _head("Yuuko Binding Flags")

    pkt = YuukoPacket(
        name  = "dir:/mnt/data",
        type  = PayloadType.JSON,
        data  = b'{"path":"/mnt/data","uuid":"abc123"}',
        flags = [YuukoFlags.BINDING_SYNC],
    )
    r.assert_true(YuukoFlags.BINDING_SYNC in pkt.flags, "binding_sync flag present")

    partial = YuukoPacket(name="chunk-001", type=PayloadType.BYTE_ARRAY,
                           data=b"\x00" * 512,
                           flags=[YuukoFlags.PARTIAL, YuukoFlags.COMPRESSED])
    r.assert_true(YuukoFlags.PARTIAL     in partial.flags, "partial flag present")
    r.assert_true(YuukoFlags.COMPRESSED  in partial.flags, "compressed flag present")


# ── 11. StreetPass full cycle ─────────────────────────────────────────────────

async def test_streetpass_cycle():
    _head("StreetPass Full Cycle (VectorGear + XRUIOS)")

    broker = LocalBroker()
    seen_vg    = []
    seen_xruios = []

    async def on_vg(pkt):     seen_vg.append(pkt)
    async def on_xruios(pkt):  seen_xruios.append(pkt)

    await broker.subscribe(YuukoTopics.VECTOR_GEAR_STREETPASS, on_vg)
    await broker.subscribe(YuukoTopics.XRUIOS_STREETPASS,       on_xruios)

    # Simulate nearby device announcements
    devices = [
        (YuukoTopics.VECTOR_GEAR_STREETPASS, "vg-abc123",
         b'{"model":"VectorGear","fw":"1.2.0","rssi":-55}'),
        (YuukoTopics.XRUIOS_STREETPASS,       "xruios-dev7",
         b'{"version":"0.9.1","theme":"DOS1999"}'),
        (YuukoTopics.VECTOR_GEAR_STREETPASS, "vg-def456",
         b'{"model":"VectorGear","fw":"1.2.0","rssi":-70}'),
    ]

    for topic, name, data in devices:
        await broker.publish(topic, YuukoPacket(name=name, type=PayloadType.JSON, data=data))

    await asyncio.sleep(0.02)
    r.assert_true(len(seen_vg)     == 2, "2 VectorGear StreetPass events received")
    r.assert_true(len(seen_xruios) == 1, "1 XRUIOS StreetPass event received")

    vg_stored = await broker.request(YuukoTopics.VECTOR_GEAR_STREETPASS)
    r.assert_true(len(vg_stored) == 2, "2 VectorGear peers in store")

    # Device leaves → tombstone
    await broker.tombstone(YuukoTopics.VECTOR_GEAR_STREETPASS, "vg-abc123")
    vg_stored2 = await broker.request(YuukoTopics.VECTOR_GEAR_STREETPASS)
    r.assert_true(len(vg_stored2) == 1, "1 VectorGear peer after departure tombstone")


# ── 12. Eclipse server probe (optional) ──────────────────────────────────────

async def test_eclipse_probe():
    _head("Eclipse Server Connectivity (optional)")

    client = EclipseClient("http://localhost:5050")
    alive  = await client.ping()

    if not alive:
        r.skip("Eclipse server not running — skipping live broker tests")
        _info("Start EclipseServer on :5050 to run these tests")
        return

    _info(f"Eclipse server reachable → running live tests")

    # Publish a test packet
    pkt = YuukoPacket(name="eclipse-test", type=PayloadType.JSON,
                       data=b'{"from":"yuuko_test.py","ok":true}')
    try:
        await client.publish(YuukoTopics.SYSTEM_DIAGNOSTICS, pkt)
        r.ok("EclipseBroker publish succeeded")
    except Exception as e:
        r.fail("EclipseBroker publish", str(e))

    try:
        stored = await client.request(YuukoTopics.SYSTEM_DIAGNOSTICS)
        r.ok(f"EclipseBroker request returned {len(stored)} packets")
    except Exception as e:
        r.fail("EclipseBroker request", str(e))


# ── 13. Single-topic smoke test ────────────────────────────────────────────────

async def test_single_topic(topic_name: str):
    _head(f"Single Topic Smoke Test — {topic_name}")

    # Resolve by attribute name or raw string
    topic_str = getattr(YuukoTopics, topic_name.upper(), None)
    if topic_str is None:
        # Try direct value match
        for attr in dir(YuukoTopics):
            if attr.upper() == topic_name.upper():
                topic_str = getattr(YuukoTopics, attr)
                break

    if topic_str is None:
        r.fail(f"Unknown topic label: {topic_name}")
        return

    _info(f"Resolved: {topic_name!r} → {topic_str!r}")

    broker = LocalBroker()
    received = []
    async def h(pkt): received.append(pkt)
    await broker.subscribe(topic_str, h)

    pkt = YuukoPacket(name="smoke-test", type=PayloadType.JSON,
                       data=b'{"smoke":true}')
    await broker.publish(topic_str, pkt)
    await asyncio.sleep(0.01)

    r.assert_true(len(received) == 1, "packet received on topic")
    stored = await broker.request(topic_str)
    r.assert_true(len(stored) == 1, "packet stored")
    r.ok(f"Smoke test passed for {topic_str!r}")


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════════════════════

async def main():
    parser = argparse.ArgumentParser(
        description="YuukoProtocol v1.1 CMD Test Harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python yuuko_test.py
              python yuuko_test.py --eclipse
              python yuuko_test.py --topic VectorGearStreetpass
              python yuuko_test.py --topic xruios_streetpass
        """)
    )
    parser.add_argument("--eclipse", action="store_true", help="Also probe the Eclipse server")
    parser.add_argument("--topic",   type=str,            help="Run single-topic smoke test")
    args = parser.parse_args()

    # Header
    print(f"\n{BOLD}{'═'*64}{RESET}")
    print(f"  {BOLD}{PURPLE}YuukoProtocol v1.1 — Test Harness{RESET}")
    print(f"  {DIM}Walker Industries R&D{RESET}")
    print(f"{BOLD}{'═'*64}{RESET}")

    t0 = time.perf_counter()

    if args.topic:
        await test_single_topic(args.topic)
    else:
        await test_topic_labels()
        await test_packet_construction()
        await test_local_pubsub()
        await test_local_request()
        await test_tombstone()
        await test_ephemeral()
        await test_fanout()
        await test_unsubscribe()
        await test_dedup()
        await test_binding_flags()
        await test_streetpass_cycle()
        if args.eclipse:
            await test_eclipse_probe()
        else:
            _head("Eclipse Server Tests")
            r.skip("Pass --eclipse to probe the live server")

    elapsed = time.perf_counter() - t0
    print(f"  {DIM}Time: {elapsed*1000:.1f} ms{RESET}")
    ok = r.summary()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    asyncio.run(main())

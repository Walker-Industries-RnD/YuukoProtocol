"""
packet.py — Core packet model for YuukoProtocol v1.1
Python mirror of YuukoPacket.cs / YuukoTopics / YuukoFlags
Walker Industries R&D
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List


# ── Payload type ──────────────────────────────────────────────────────────────

class PayloadType(str, Enum):
    JSON         = "Json"
    BYTES        = "Bytes"
    BYTE_ARRAY   = "ByteArray"
    MEMORY_MAPPED = "MemoryMapped"


# ── Topic constants ───────────────────────────────────────────────────────────

class YuukoTopics:
    # StreetPass
    VECTOR_GEAR_STREETPASS  = "yuuko/streetpass/vectorgear"
    XRUIOS_STREETPASS        = "yuuko/streetpass/xruios"
    GATEWAY_STREETPASS       = "yuuko/streetpass/gateway"

    # Yuuko Bindings
    BINDINGS_DIRECTORIES     = "yuuko/bindings/directories"
    BINDINGS_FILES           = "yuuko/bindings/files"

    # Vector Gear
    VECTOR_GEAR_SENSORS      = "yuuko/vectorgear/sensors"
    VECTOR_GEAR_TRACKING     = "yuuko/vectorgear/tracking"
    VECTOR_GEAR_STATUS       = "yuuko/vectorgear/status"

    # XRUIOS
    XRUIOS_CONFIG            = "yuuko/xruios/config"
    XRUIOS_EVENTS            = "yuuko/xruios/events"
    XRUIOS_SYNC              = "yuuko/xruios/sync"

    # Walker Gateway
    GATEWAY_MESH             = "yuuko/gateway/mesh"
    GATEWAY_PEERS            = "yuuko/gateway/peers"

    # Shinra Meisin
    SHINRA_EYE_TRACKING      = "yuuko/shinra/eye"
    SHINRA_FACE_TRACKING     = "yuuko/shinra/face"

    # System
    SYSTEM_HEARTBEAT         = "yuuko/system/heartbeat"
    SYSTEM_DIAGNOSTICS       = "yuuko/system/diagnostics"


# ── Packet flags ──────────────────────────────────────────────────────────────

class YuukoFlags:
    TOMBSTONE    = "tombstone"
    EPHEMERAL    = "ephemeral"
    COMPRESSED   = "compressed"
    SIGNED       = "signed"
    BINDING_SYNC = "binding_sync"
    RATE_LIMITED = "rate_limited"
    PARTIAL      = "partial"


# ── YuukoPacket ───────────────────────────────────────────────────────────────

@dataclass
class YuukoPacket:
    name:  str
    type:  PayloadType
    data:  bytes
    flags: List[str] = field(default_factory=list)

    # ── Flag helpers ──────────────────────────────────────────────────────────

    def is_tombstone(self)  -> bool: return YuukoFlags.TOMBSTONE  in self.flags
    def is_ephemeral(self)  -> bool: return YuukoFlags.EPHEMERAL  in self.flags
    def is_compressed(self) -> bool: return YuukoFlags.COMPRESSED in self.flags
    def is_signed(self)     -> bool: return YuukoFlags.SIGNED     in self.flags

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        import base64
        return {
            "name":  self.name,
            "type":  self.type.value,
            "data":  base64.b64encode(self.data).decode(),
            "flags": list(self.flags),
        }

    @staticmethod
    def from_dict(d: dict) -> "YuukoPacket":
        import base64
        return YuukoPacket(
            name  = d["name"],
            type  = PayloadType(d["type"]),
            data  = base64.b64decode(d["data"]),
            flags = list(d.get("flags", [])),
        )

    def to_json(self) -> str:
        import json
        return json.dumps(self.to_dict())

    @staticmethod
    def from_json(s: str) -> "YuukoPacket":
        import json
        return YuukoPacket.from_dict(json.loads(s))

    def data_as_string(self) -> str:
        return self.data.decode("utf-8")

    def __repr__(self) -> str:
        return (f"YuukoPacket(name={self.name!r}, type={self.type.value}, "
                f"data_len={len(self.data)}, flags={self.flags})")

// YuukoPacket.cs
// Core packet model for YuukoProtocol v1.1
// Walker Industries R&D

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace YuukoProtocol
{
    // ── Payload type ─────────────────────────────────────────────────────────

    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum PayloadType
    {
        Json,
        Bytes,
        ByteArray,
        MemoryMapped
    }

    // ── Named topic labels ────────────────────────────────────────────────────

    /// <summary>
    /// Canonical topic string constants for the Walker Industries ecosystem.
    /// Use these instead of raw strings everywhere.
    /// </summary>
    public static class YuukoTopics
    {
        // ── StreetPass ───────────────────────────────────────────────────────
        public const string VectorGearStreetpass  = "yuuko/streetpass/vectorgear";
        public const string XRUIOSStreetpass       = "yuuko/streetpass/xruios";
        public const string GatewayStreetpass      = "yuuko/streetpass/gateway";

        // ── Yuuko Bindings ───────────────────────────────────────────────────
        public const string BindingsDirectories    = "yuuko/bindings/directories";
        public const string BindingsFiles          = "yuuko/bindings/files";

        // ── Vector Gear ──────────────────────────────────────────────────────
        public const string VectorGearSensors      = "yuuko/vectorgear/sensors";
        public const string VectorGearTracking     = "yuuko/vectorgear/tracking";
        public const string VectorGearStatus       = "yuuko/vectorgear/status";

        // ── XRUIOS ───────────────────────────────────────────────────────────
        public const string XRUIOSConfig           = "yuuko/xruios/config";
        public const string XRUIOSEvents           = "yuuko/xruios/events";
        public const string XRUIOSSync             = "yuuko/xruios/sync";

        // ── Walker Gateway ───────────────────────────────────────────────────
        public const string GatewayMesh            = "yuuko/gateway/mesh";
        public const string GatewayPeers           = "yuuko/gateway/peers";

        // ── Shinra Meisin ────────────────────────────────────────────────────
        public const string ShinraEyeTracking      = "yuuko/shinra/eye";
        public const string ShinraFaceTracking     = "yuuko/shinra/face";

        // ── System ───────────────────────────────────────────────────────────
        public const string SystemHeartbeat        = "yuuko/system/heartbeat";
        public const string SystemDiagnostics      = "yuuko/system/diagnostics";
    }

    // ── Packet flags ──────────────────────────────────────────────────────────

    public static class YuukoFlags
    {
        public const string Tombstone    = "tombstone";
        public const string Ephemeral    = "ephemeral";
        public const string Compressed   = "compressed";
        public const string Signed       = "signed";
        public const string BindingSync  = "binding_sync";
        public const string RateLimited  = "rate_limited";
        public const string Partial      = "partial";
    }

    // ── YuukoPacket ───────────────────────────────────────────────────────────

    /// <summary>
    /// Atomic data unit for YuukoProtocol.
    /// Eclipse decrypts payload before handing this to application code.
    /// </summary>
    public sealed class YuukoPacket
    {
        [JsonPropertyName("name")]
        public string Name { get; init; } = string.Empty;

        [JsonPropertyName("type")]
        public PayloadType Type { get; init; } = PayloadType.Bytes;

        [JsonPropertyName("data")]
        public byte[] Data { get; init; } = Array.Empty<byte>();

        [JsonPropertyName("flags")]
        public List<string> Flags { get; init; } = new();

        // ── Helpers ───────────────────────────────────────────────────────────

        public bool IsTombstone  => Flags.Contains(YuukoFlags.Tombstone);
        public bool IsEphemeral  => Flags.Contains(YuukoFlags.Ephemeral);
        public bool IsCompressed => Flags.Contains(YuukoFlags.Compressed);
        public bool IsSigned     => Flags.Contains(YuukoFlags.Signed);

        // ── Factories ─────────────────────────────────────────────────────────

        public static YuukoPacket FromString(string name, string json) =>
            new() { Name = name, Type = PayloadType.Json, Data = Encoding.UTF8.GetBytes(json) };

        public static YuukoPacket FromBytes(string name, byte[] data) =>
            new() { Name = name, Type = PayloadType.Bytes, Data = data };

        public static YuukoPacket Tombstone(string name) =>
            new() { Name = name, Type = PayloadType.Bytes, Data = Array.Empty<byte>(), Flags = { YuukoFlags.Tombstone } };

        public static YuukoPacket Ephemeral(string name, byte[] data) =>
            new() { Name = name, Type = PayloadType.Bytes, Data = data, Flags = { YuukoFlags.Ephemeral } };

        // ── Serialisation ─────────────────────────────────────────────────────

        public string ToJson() => JsonSerializer.Serialize(this, YuukoJson.Options);

        public static YuukoPacket? FromJson(string json) =>
            JsonSerializer.Deserialize<YuukoPacket>(json, YuukoJson.Options);

        public string DataAsString() => Encoding.UTF8.GetString(Data);

        public override string ToString() =>
            $"YuukoPacket {{ Name={Name}, Type={Type}, DataLen={Data.Length}, Flags=[{string.Join(",", Flags)}] }}";
    }

    // ── JSON options singleton ────────────────────────────────────────────────

    internal static class YuukoJson
    {
        public static readonly JsonSerializerOptions Options = new()
        {
            WriteIndented        = false,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        };
    }
}

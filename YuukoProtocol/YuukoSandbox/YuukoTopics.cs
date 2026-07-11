using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace YuukoSandbox
{
    public static class YuukoTopics
    {
        // ── StreetPass ───────────────────────────────────────────────────────
        public const string VectorGearStreetpass = "yuuko/streetpass/vectorgear";
        public const string XRUIOSStreetpass = "yuuko/streetpass/xruios";
        public const string GatewayStreetpass = "yuuko/streetpass/gateway";

        // ── Yuuko Bindings ───────────────────────────────────────────────────
        public const string BindingsDirectories = "yuuko/bindings/directories";
        public const string BindingsFiles = "yuuko/bindings/files";

        // ── Vector Gear ──────────────────────────────────────────────────────
        public const string VectorGearSensors = "yuuko/vectorgear/sensors";
        public const string VectorGearTracking = "yuuko/vectorgear/tracking";
        public const string VectorGearStatus = "yuuko/vectorgear/status";

        // ── XRUIOS ───────────────────────────────────────────────────────────
        public const string XRUIOSConfig = "yuuko/xruios/config";
        public const string XRUIOSEvents = "yuuko/xruios/events";
        public const string XRUIOSSync = "yuuko/xruios/sync";

        // ── Walker Gateway ───────────────────────────────────────────────────
        public const string GatewayMesh = "yuuko/gateway/mesh";
        public const string GatewayPeers = "yuuko/gateway/peers";

        // ── Shinra Meisin ────────────────────────────────────────────────────
        public const string ShinraEyeTracking = "yuuko/shinra/eye";
        public const string ShinraFaceTracking = "yuuko/shinra/face";

        // ── System ───────────────────────────────────────────────────────────
        public const string SystemHeartbeat = "yuuko/system/heartbeat";
        public const string SystemDiagnostics = "yuuko/system/diagnostics";
    }
}

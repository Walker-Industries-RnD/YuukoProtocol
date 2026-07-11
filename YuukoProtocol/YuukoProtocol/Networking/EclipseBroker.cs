// EclipseBroker.cs
// Secure request/response overlay over any IYuukoApi transport (ZenohBroker in
// production, LocalBroker for tests). Replaces the old HTTP+WebSocket-to-Eclipse-server
// design: instead of a central Eclipse RPC hub, each node handshakes peer-to-peer via
// YuukoHandshake and serves data encrypted per established peer.
//
// Roles (a node can be both):
//   Provider  — Serve(topic, packet) puts data in a local store; incoming DATA_REQ from a
//               handshaked peer is answered with the matching packets, encrypted end-to-end.
//   Requester — RequestAsync(providerId, topic) does a handshake if needed, then asks the
//               provider for a topic and returns the decrypted packets.
//
// All crypto runs through the Eclipse DLL (EclipseProject.Security.AeadChannel) via the
// per-peer HandshakeSession. Only handshake + ciphertext ever touch the transport.
//
// Walker Industries R&D — YuukoProtocol v1.3 (Eclipse-secured, Zenoh-transported)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{
    public sealed class EclipseBrokerOptions
    {
        /// <summary>Key expression carrying encrypted DATA_REQ / DATA_RESP messages.</summary>
        public string DataTopic { get; set; } = "yuuko/eclipse/data";

        /// <summary>How long RequestAsync waits for a reply before giving up.</summary>
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>Handshake tuning (banned list, PSK, handshake topic, timeout).</summary>
        public HandshakeOptions Handshake { get; } = new();
    }

    public sealed class EclipseBroker : IDisposable
    {
        private readonly IYuukoApi _transport;
        private readonly YuukoIdentity _identity;
        private readonly YuukoHandshake _handshake;
        private readonly EclipseBrokerOptions _opts;

        // Provider: retained packets per data topic (name -> packet), tombstone/ephemeral aware.
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, YuukoPacket>> _store = new();

        // Requester: in-flight requests awaiting a reply, keyed by request id.
        private readonly ConcurrentDictionary<string, TaskCompletionSource<IReadOnlyList<YuukoPacket>>> _pending = new();

        private Func<YuukoPacket, Task>? _dataSub;
        private int _disposed;

        private EclipseBroker(IYuukoApi transport, YuukoIdentity identity, EclipseBrokerOptions opts)
        {
            _transport = transport;
            _identity = identity;
            _opts = opts;
            _handshake = new YuukoHandshake(transport, identity, opts.Handshake);
        }

        public string ClientId => _identity.ClientId;

        /// <summary>Wraps <paramref name="transport"/> with an Eclipse-secured overlay for <paramref name="identity"/>.</summary>
        public static EclipseBroker Create(IYuukoApi transport, YuukoIdentity identity, EclipseBrokerOptions? options = null)
        {
            if (transport is null) throw new ArgumentNullException(nameof(transport));
            if (identity is null) throw new ArgumentNullException(nameof(identity));
            return new EclipseBroker(transport, identity, options ?? new EclipseBrokerOptions());
        }

        /// <summary>Begins answering handshakes and data requests. Idempotent.</summary>
        public async Task StartAsync(CancellationToken ct = default)
        {
            ThrowIfDisposed();
            if (_dataSub is not null) return;

            await _handshake.StartAsync(ct);

            _dataSub = pkt => OnDataMessageAsync(pkt);
            await _transport.SubscribeAsync(_opts.DataTopic, _dataSub, ct);
        }

        // ── Provider API ─────────────────────────────────────────────────────────

        /// <summary>Publishes a packet into the local store so handshaked peers can request it.</summary>
        public void Serve(string dataTopic, YuukoPacket packet)
        {
            ThrowIfDisposed();
            var store = _store.GetOrAdd(dataTopic, _ => new ConcurrentDictionary<string, YuukoPacket>());

            if (packet.IsTombstone) { store.TryRemove(packet.Name, out _); return; }
            if (packet.IsEphemeral) return; // never retained, matches LocalBroker
            store[packet.Name] = packet;
        }

        // ── Requester API ────────────────────────────────────────────────────────

        /// <summary>
        /// Ensures a session with <paramref name="providerId"/> (handshaking if needed), then
        /// requests all retained packets on <paramref name="dataTopic"/>, decrypted.
        /// Returns an empty list on rejection/timeout.
        /// </summary>
        public async Task<IReadOnlyList<YuukoPacket>> RequestAsync(
            string providerId, string dataTopic, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            await StartAsync(ct);

            var session = await _handshake.RequestSessionAsync(providerId, ct);
            if (session is null) return Array.Empty<YuukoPacket>();

            // Borrow one of the session's parallel lanes; this bounds concurrency to the
            // session's lane count while allowing that many requests to a peer at once.
            int lane = await session.AcquireLaneAsync(ct);
            try
            {
                var requestId = Guid.NewGuid().ToString("N");
                var tcs = new TaskCompletionSource<IReadOnlyList<YuukoPacket>>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                _pending[requestId] = tcs;

                try
                {
                    byte[] enc = session.EncryptOnLane(lane, "REQ", Encoding.UTF8.GetBytes(dataTopic));
                    await SendAsync(DataType.Req, providerId, requestId, lane, enc, ct);

                    using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeout.CancelAfter(_opts.RequestTimeout);
                    using (timeout.Token.Register(() => tcs.TrySetResult(Array.Empty<YuukoPacket>())))
                        return await tcs.Task.ConfigureAwait(false);
                }
                finally
                {
                    _pending.TryRemove(requestId, out _);
                }
            }
            finally
            {
                session.ReleaseLane(lane);
            }
        }

        // ── Message handling ───────────────────────────────────────────────────────

        private async Task OnDataMessageAsync(YuukoPacket pkt)
        {
            var msg = DataWire.Decode(pkt.Data);
            if (msg is null) return;
            if (!string.Equals(msg.ToId, _identity.ClientId, StringComparison.Ordinal)) return;

            if (msg.Type == DataType.Req) await OnRequestAsync(msg);
            else if (msg.Type == DataType.Resp) OnResponse(msg);
        }

        private async Task OnRequestAsync(DataMessage req)
        {
            // Only serve peers that have completed a handshake.
            if (!_handshake.TryGetSession(req.FromId, out var session)) return;
            if (req.Payload is null) return;

            IReadOnlyList<YuukoPacket> packets;
            try
            {
                string dataTopic = Encoding.UTF8.GetString(session.DecryptOnLane(req.Lane, req.Payload));
                packets = _store.TryGetValue(dataTopic, out var store)
                    ? store.Values.ToList()
                    : Array.Empty<YuukoPacket>();
            }
            catch { return; } // decrypt failed => not a valid peer message, drop

            // Answer on the same lane the request arrived on.
            byte[] enc = session.EncryptOnLane(req.Lane, "RESP", DataWire.EncodePackets(packets));
            await SendAsync(DataType.Resp, req.FromId, req.RequestId, req.Lane, enc);
        }

        private void OnResponse(DataMessage resp)
        {
            if (!_pending.TryGetValue(resp.RequestId, out var tcs)) return;
            if (resp.Payload is null) { tcs.TrySetResult(Array.Empty<YuukoPacket>()); return; }
            if (!_handshake.TryGetSession(resp.FromId, out var session)) return;

            try
            {
                var packets = DataWire.DecodePackets(session.DecryptOnLane(resp.Lane, resp.Payload));
                tcs.TrySetResult(packets);
            }
            catch
            {
                tcs.TrySetResult(Array.Empty<YuukoPacket>());
            }
        }

        private Task SendAsync(DataType type, string toId, string requestId, int lane, byte[] payload, CancellationToken ct = default)
        {
            var msg = new DataMessage
            {
                Type = type,
                FromId = _identity.ClientId,
                ToId = toId,
                RequestId = requestId,
                Lane = lane,
                Payload = payload,
            };
            var packet = YuukoPacket.Ephemeral(type + ":" + requestId, DataWire.Encode(msg));
            return _transport.PublishAsync(_opts.DataTopic, packet, ct);
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(EclipseBroker));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            if (_dataSub is not null)
                _ = _transport.UnsubscribeAsync(_opts.DataTopic, _dataSub);

            _handshake.Dispose();
            _store.Clear();
        }

        // ── Wire types ─────────────────────────────────────────────────────────────

        private enum DataType { Req, Resp }

        private sealed class DataMessage
        {
            public DataType Type { get; set; }
            public string FromId { get; set; } = "";
            public string ToId { get; set; } = "";
            public string RequestId { get; set; } = "";
            public int Lane { get; set; }
            public byte[]? Payload { get; set; } // AeadChannel-encrypted envelope bytes
        }

        private static class DataWire
        {
            private static readonly JsonSerializerOptions Json = new()
            {
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            };

            public static byte[] Encode(DataMessage m) => JsonSerializer.SerializeToUtf8Bytes(m, Json);

            public static DataMessage? Decode(byte[] data)
            {
                try { return JsonSerializer.Deserialize<DataMessage>(data, Json); }
                catch { return null; }
            }

            public static byte[] EncodePackets(IReadOnlyList<YuukoPacket> packets) =>
                JsonSerializer.SerializeToUtf8Bytes(packets, Json);

            public static IReadOnlyList<YuukoPacket> DecodePackets(byte[] data) =>
                JsonSerializer.Deserialize<List<YuukoPacket>>(data, Json) ?? new List<YuukoPacket>();
        }
    }
}

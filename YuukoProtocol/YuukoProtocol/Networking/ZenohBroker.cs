// ZenohBroker.cs
// Production IYuukoApi implementation over Zenoh — a peer-to-peer / router-optional
// replacement for EclipseBroker's HTTP+WebSocket transport.
//
// Transport model:
//   PublishAsync    -> Publisher.Put()            (declared once per topic, reused)
//   SubscribeAsync  -> Session.DeclareSubscriber() (one native subscriber per topic,
//                                                   fanned out to N managed handlers)
//   RequestAsync    -> Session.Get()               (Zenoh query/reply), merged with
//                       whatever this broker already holds locally
//   (unused)        -> Session.DeclareQueryable()  answers other peers' Get() calls
//                       with this broker's local retained-packet store
//
// Wire format: packets stay UTF-8 JSON via YuukoPacket.ToJson()/FromJson(), tagged
// with the Zenoh "application/json" encoding, so any other Zenoh client (zenoh-python
// tooling, the REST plugin, zenohd storages) can read them without knowing about
// YuukoProtocol's C# types.
//
// Retained/tombstone/ephemeral semantics mirror LocalBroker: each ZenohBroker instance
// keeps an in-memory store per topic, updated on every local publish and every sample
// it receives. That store both answers RequestAsync locally and backs this broker's
// own Queryable, so a swarm of ZenohBroker peers behaves like a replicated LocalBroker
// with zero central server required (a zenohd router is only needed to bridge peers
// that can't reach each other directly, e.g. across NAT boundaries).
//
// Dependency: NuGet package "Zenoh-CS" (github.com/sanri/zenoh-csharp), a managed
// wrapper over the native zenoh-c library. See the notes at the bottom of this file
// for setup — the native zenoh-c binary is NOT distributed via NuGet and must be
// installed on the host separately, pinned to the version Zenoh-CS was built against.
//
// Walker Industries R&D — YuukoProtocol v1.2 (Zenoh transport)

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Zenoh;
using ZEncoding = Zenoh.Encoding;

namespace YuukoProtocol
{
    // ── Configuration ────────────────────────────────────────────────────────

    public enum ZenohSessionMode
    {
        /// <summary>Full mesh participant — can talk directly to other peers, no router required.</summary>
        Peer,

        /// <summary>Connects through a zenohd router only; lighter weight, good for constrained devices.</summary>
        Client
    }

    /// <summary>Connection + behavior tuning for <see cref="ZenohBroker"/>.</summary>
    public sealed class ZenohBrokerOptions
    {
        public ZenohSessionMode Mode { get; set; } = ZenohSessionMode.Peer;

        /// <summary>e.g. "tcp/192.168.1.10:7447". Leave empty for multicast peer discovery.</summary>
        public List<string> ConnectEndpoints { get; } = new();

        /// <summary>Endpoints this session should listen on, e.g. "tcp/0.0.0.0:7447".</summary>
        public List<string> ListenEndpoints { get; } = new();

        /// <summary>Zenoh query timeout for RequestAsync, in milliseconds.</summary>
        public ulong GetTimeoutMs { get; set; } = 2500;

        /// <summary>Reply channel capacity for RequestAsync.</summary>
        public uint GetChannelCapacity { get; set; } = 64;

        /// <summary>
        /// If true, subscribing to a topic also declares a Queryable that answers other
        /// peers' RequestAsync/Get() calls with this broker's retained packets.
        /// Disable on read-only / thin clients that shouldn't serve as a storage node.
        /// </summary>
        public bool AnswerQueries { get; set; } = true;

        // ── TLS (transport-layer security) ─────────────────────────────────────
        // Optional link encryption underneath EclipseBroker's per-peer AES-256-GCM.
        // Toggle with EnableTls. When on, tcp/ endpoints are switched to tls/ and the
        // certificate material below is applied. Zenoh's rustls stack negotiates
        // TLS 1.3 with capable peers (falling back to 1.2 only if a peer can't do 1.3).

        //I might remove 1.2 functionality and enforce PQC Encryption, IDK yet

        /// <summary>Master switch: enable/disable TLS on all Zenoh links. Default off.</summary>
        public bool EnableTls { get; set; } = false;

        /// <summary>Path to the PEM root CA used to verify the peer's certificate.</summary>
        public string? TlsRootCaCertificate { get; set; }

        /// <summary>Path to the PEM certificate this node presents when listening.</summary>
        public string? TlsListenCertificate { get; set; }

        /// <summary>Path to the PEM private key for <see cref="TlsListenCertificate"/>.</summary>
        public string? TlsListenPrivateKey { get; set; }

        /// <summary>Path to the PEM certificate this node presents when connecting (mTLS).</summary>
        public string? TlsConnectCertificate { get; set; }

        /// <summary>Path to the PEM private key for <see cref="TlsConnectCertificate"/>.</summary>
        public string? TlsConnectPrivateKey { get; set; }

        /// <summary>Require the peer to present a valid certificate (mutual TLS).</summary>
        public bool TlsEnableMutual { get; set; } = false;

        /// <summary>Verify the peer certificate's name on connect. Off eases self-signed/dev setups.</summary>
        public bool TlsVerifyNameOnConnect { get; set; } = false;
    }

    // ── ZenohBroker ──────────────────────────────────────────────────────────

    public sealed class ZenohBroker : IYuukoApi, IDisposable
    {
        private readonly Session _session;
        private readonly ZenohBrokerOptions _opts;

        private readonly ConcurrentDictionary<string, Publisher> _publishers = new();
        private readonly ConcurrentDictionary<string, Subscriber> _subscribers = new();
        private readonly ConcurrentDictionary<string, Zenoh.Queryable> _queryables = new();
        private readonly ConcurrentDictionary<string, List<Func<YuukoPacket, Task>>> _handlers = new();
        private readonly ConcurrentDictionary<string, ConcurrentDictionary<string, YuukoPacket>> _store = new();

        private readonly object _declareLock = new();
        private int _disposed;

        private ZenohBroker(Session session, ZenohBrokerOptions opts)
        {
            _session = session;
            _opts = opts;
        }

        // ── Factory ──────────────────────────────────────────────────────────

        /// <summary>
        /// Opens a Zenoh session and returns a ready-to-use broker.
        /// Throws if the underlying zenoh-c session can't be opened (bad config,
        /// no reachable peer/router in Client mode, native library missing, etc).
        /// </summary>
        public static ZenohBroker Open(ZenohBrokerOptions? options = null)
        {
            options ??= new ZenohBrokerOptions();

            using var config = BuildConfig(options)
                ?? throw new InvalidOperationException("ZenohBroker: failed to parse generated Zenoh config JSON5.");

            var result = Session.Open(config, out var session);
            if (session is null)
                throw new InvalidOperationException(
                    $"ZenohBroker: Session.Open failed ({result}). Is the native zenoh-c library installed, " +
                    $"and (in Client mode) is a zenohd router reachable?");

            return new ZenohBroker(session, options);
        }

        private static Config? BuildConfig(ZenohBrokerOptions o)
        {
            // JSON string literal with proper escaping (Windows cert paths contain backslashes).
            static string J(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

            // When TLS is on, present every tcp/ endpoint as tls/ (leave already-tls/quic alone).
            string Endpoint(string ep) =>
                o.EnableTls && ep.StartsWith("tcp/", StringComparison.OrdinalIgnoreCase)
                    ? "tls/" + ep.Substring(4)
                    : ep;

            string Arr(IEnumerable<string> e) => string.Join(",", e.Select(x => J(Endpoint(x))));

            var modeStr = o.Mode == ZenohSessionMode.Client ? "client" : "peer";

            var json = "{\"mode\":\"" + modeStr + "\"" +
                (o.ConnectEndpoints.Count > 0 ? ",\"connect\":{\"endpoints\":[" + Arr(o.ConnectEndpoints) + "]}" : "") +
                (o.ListenEndpoints.Count > 0 ? ",\"listen\":{\"endpoints\":[" + Arr(o.ListenEndpoints) + "]}" : "") +
                BuildTlsBlock(o, J) +
                "}";

            return Config.FromStr(json);
        }

        // Emits ,"transport":{"link":{"tls":{...}}} when EnableTls, else "".
        // NOTE: these keys track the zenoh-c config schema — verify against your pinned
        // zenoh-c (1.6.2) if a key is rejected; TLS itself is what forces link encryption.
        private static string BuildTlsBlock(ZenohBrokerOptions o, Func<string, string> J)
        {
            if (!o.EnableTls) return "";

            var fields = new List<string>();
            void Add(string key, string? path)
            {
                if (!string.IsNullOrWhiteSpace(path)) fields.Add("\"" + key + "\":" + J(path!));
            }

            Add("root_ca_certificate", o.TlsRootCaCertificate);
            Add("listen_certificate", o.TlsListenCertificate);
            Add("listen_private_key", o.TlsListenPrivateKey);
            Add("connect_certificate", o.TlsConnectCertificate);
            Add("connect_private_key", o.TlsConnectPrivateKey);
            fields.Add("\"enable_mtls\":" + (o.TlsEnableMutual ? "true" : "false"));
            fields.Add("\"verify_name_on_connect\":" + (o.TlsVerifyNameOnConnect ? "true" : "false"));

            return ",\"transport\":{\"link\":{\"tls\":{" + string.Join(",", fields) + "}}}";
        }

        // ── IYuukoApi: Publish ──────────────────────────────────────────────

        public Task PublishAsync(string topic, YuukoPacket packet, CancellationToken ct = default)
        {
            ThrowIfDisposed();
            ApplyToStore(topic, packet);

            var publisher = GetOrDeclarePublisher(topic);

            var bytes = System.Text.Encoding.UTF8.GetBytes(packet.ToJson());
            using var payload = ZBytes.FromBytes(bytes);
            using var putOptions = new PublisherPutOptions { Encoding = new ZEncoding(EncodingId.ApplicationJson) };

            var result = publisher.Put(payload, putOptions);
            if (result != Result.Ok)
                throw new InvalidOperationException($"ZenohBroker: publish on '{topic}' failed ({result}).");

            return Task.CompletedTask;
        }

        // ── IYuukoApi: Subscribe / Unsubscribe ──────────────────────────────

        public Task SubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            ThrowIfDisposed();

            var list = _handlers.GetOrAdd(topic, _ => new List<Func<YuukoPacket, Task>>());
            lock (list) list.Add(handler);

            EnsureSubscriber(topic);
            if (_opts.AnswerQueries) EnsureQueryable(topic);

            return Task.CompletedTask;
        }

        public Task UnsubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            if (_handlers.TryGetValue(topic, out var list))
                lock (list) list.RemoveAll(h => h == handler);

            // Native subscriber/queryable are intentionally left declared — topics are
            // cheap to keep open and other local handlers may still be registered.
            // Dispose() tears everything down on broker shutdown.
            return Task.CompletedTask;
        }

        // ── IYuukoApi: Request (Zenoh Get / query-reply) ────────────────────

        public Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default)
        {
            ThrowIfDisposed();

            var merged = new Dictionary<string, YuukoPacket>();
            if (_store.TryGetValue(topic, out var local))
                foreach (var kv in local) merged[kv.Key] = kv.Value;

            return Task.Run(() =>
            {
                using var keyexpr = Keyexpr.FromString(topic)
                    ?? throw new ArgumentException($"'{topic}' is not a valid Zenoh key expression.", nameof(topic));

                using var getOptions = new GetOptions { Timeout = _opts.GetTimeoutMs };

                _session.Get(keyexpr, getOptions, null, ChannelType.Fifo, _opts.GetChannelCapacity, out var channel);
                if (channel is null)
                    return (IReadOnlyList<YuukoPacket>)merged.Values.ToList().AsReadOnly();

                using (channel)
                {
                    while (true)
                    {
                        ct.ThrowIfCancellationRequested();

                        var r = channel.Recv(out var reply);
                        if (reply is null)
                        {
                            if (r == Result.ChannelDisconnected) break; // query complete
                            continue;
                        }

                        using (reply)
                        {
                            if (!reply.IsOk()) continue;

                            var sample = reply.AsOk();
                            if (sample is null) continue;

                            var packet = SampleToPacket(sample);
                            if (packet is null) continue;

                            if (packet.IsTombstone) merged.Remove(packet.Name);
                            else merged[packet.Name] = packet;
                        }
                    }
                }

                return (IReadOnlyList<YuukoPacket>)merged.Values.ToList().AsReadOnly();
            }, ct);
        }

        // ── Internals: declare-once publishers / subscribers / queryables ───

        private Publisher GetOrDeclarePublisher(string topic)
        {
            if (_publishers.TryGetValue(topic, out var existing)) return existing;

            lock (_declareLock)
            {
                if (_publishers.TryGetValue(topic, out existing)) return existing;

                using var keyexpr = Keyexpr.FromString(topic)
                    ?? throw new ArgumentException($"'{topic}' is not a valid Zenoh key expression.", nameof(topic));

                using var options = new PublisherOptions();
                var result = _session.DeclarePublisher(keyexpr, options, out var publisher);
                if (publisher is null)
                    throw new InvalidOperationException($"ZenohBroker: declare_publisher('{topic}') failed ({result}).");

                _publishers[topic] = publisher;
                return publisher;
            }
        }

        private void EnsureSubscriber(string topic)
        {
            if (_subscribers.ContainsKey(topic)) return;

            lock (_declareLock)
            {
                if (_subscribers.ContainsKey(topic)) return;

                using var keyexpr = Keyexpr.FromString(topic)
                    ?? throw new ArgumentException($"'{topic}' is not a valid Zenoh key expression.", nameof(topic));

                var options = new SubscriberOptions();

                var result = _session.DeclareSubscriber(keyexpr, options, sample => OnSample(topic, sample), out var subscriber);
                if (subscriber is null)
                    throw new InvalidOperationException($"ZenohBroker: declare_subscriber('{topic}') failed ({result}).");

                _subscribers[topic] = subscriber;
            }
        }

        private void EnsureQueryable(string topic)
        {
            if (_queryables.ContainsKey(topic)) return;

            lock (_declareLock)
            {
                if (_queryables.ContainsKey(topic)) return;

                using var keyexpr = Keyexpr.FromString(topic)
                    ?? throw new ArgumentException($"'{topic}' is not a valid Zenoh key expression.", nameof(topic));

                var options = new QueryableOptions { Complete = true };

                var result = _session.DeclareQueryable(keyexpr, options, query => OnQuery(topic, query), out var queryable);
                if (queryable is null)
                    throw new InvalidOperationException($"ZenohBroker: declare_queryable('{topic}') failed ({result}).");

                _queryables[topic] = queryable;
            }
        }

        // Runs on Zenoh's native dispatch thread. Extract everything synchronously,
        // then hand off to the managed pipeline so we never block zenoh-c's runtime.
        private void OnSample(string topic, Sample sample)
        {
            var packet = SampleToPacket(sample);
            if (packet is null) return;

            ApplyToStore(topic, packet);

            if (!_handlers.TryGetValue(topic, out var list)) return;

            List<Func<YuukoPacket, Task>> snapshot;
            lock (list) snapshot = new List<Func<YuukoPacket, Task>>(list);
            if (snapshot.Count == 0) return;

            _ = Task.Run(async () =>
            {
                foreach (var h in snapshot)
                {
                    try   { await h(packet); }
                    catch { /* isolate faults per handler, mirrors LocalBroker */ }
                }
            });
        }

        // Runs on Zenoh's native dispatch thread. Answers a peer's Get() with every
        // packet this broker currently retains for the topic.
        private void OnQuery(string topic, Query query)
        {
            if (!_store.TryGetValue(topic, out var store) || store.IsEmpty) return;

            using var keyexpr = Keyexpr.FromString(topic);
            if (keyexpr is null) return;

            foreach (var packet in store.Values.ToList())
            {
                var bytes = System.Text.Encoding.UTF8.GetBytes(packet.ToJson());
                var payload = ZBytes.FromBytes(bytes); // ownership moves into query.Reply()
                using var replyOptions = new QueryReplyOptions { Encoding = new ZEncoding(EncodingId.ApplicationJson) };

                query.Reply(keyexpr, payload, replyOptions);
            }
        }

        private static YuukoPacket? SampleToPacket(Sample sample)
        {
            if (sample.GetKind() == SampleKind.Delete) return null; // raw z_delete, unused by YuukoProtocol

            try
            {
                using var payload = sample.GetPayload();
                var json = System.Text.Encoding.UTF8.GetString(payload.ToByteArray());
                return YuukoPacket.FromJson(json);
            }
            catch { return null; } // malformed / foreign payload on this key expression
        }

        private void ApplyToStore(string topic, YuukoPacket packet)
        {
            var store = _store.GetOrAdd(topic, _ => new ConcurrentDictionary<string, YuukoPacket>());

            if (packet.IsTombstone) { store.TryRemove(packet.Name, out _); return; }
            if (packet.IsEphemeral) return; // never retained, matches LocalBroker

            store[packet.Name] = packet;
        }

        // ── Lifecycle ────────────────────────────────────────────────────────

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new ObjectDisposedException(nameof(ZenohBroker));
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            foreach (var q in _queryables.Values) q.Dispose();
            foreach (var s in _subscribers.Values) s.Dispose();
            foreach (var p in _publishers.Values) p.Dispose();

            _session.Close();
            _session.Dispose();
        }
    }
}


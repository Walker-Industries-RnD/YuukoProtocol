// EclipseBroker.cs
// Production IYuukoApi implementation — routes through the Eclipse RPC server.
// Eclipse handles ALL Kyber-1024 + AES-256-GCM cryptography.
// This class only deals in plaintext packets.
//
// Walker Industries R&D — YuukoProtocol v1.1

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{
    /// <summary>
    /// Production broker: delegates pub/sub to the C# Eclipse RPC server.
    /// Requires EclipseServer to be running (default port 5050).
    ///
    /// Publish/Request use HTTP POST to /dirac/Yuuko*.
    /// Subscribe opens a WebSocket to /subscribe/{topic}.
    /// </summary>
    public sealed class EclipseBroker : IYuukoApi, IDisposable
    {
        private readonly HttpClient _http;
        private readonly string     _wsBase;
        private readonly ConcurrentDictionary<string, List<Func<YuukoPacket, Task>>> _subs = new();
        private readonly List<Task> _wsTasks = new();
        private readonly CancellationTokenSource _cts = new();

        public EclipseBroker(string eclipseBase = "http://localhost:5050")
        {
            _http   = new HttpClient { BaseAddress = new Uri(eclipseBase) };
            _wsBase = eclipseBase
                .Replace("https://", "wss://", StringComparison.OrdinalIgnoreCase)
                .Replace("http://",  "ws://",  StringComparison.OrdinalIgnoreCase);
        }

        // ── IYuukoApi ─────────────────────────────────────────────────────────

        public async Task PublishAsync(string topic, YuukoPacket packet, CancellationToken ct = default)
        {
            var payload = new { topic, packet };
            var resp = await _http.PostAsJsonAsync("/dirac/YuukoPublish", payload, ct);
            resp.EnsureSuccessStatusCode();
        }

        public async Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default)
        {
            var payload = new { topic };
            var resp    = await _http.PostAsJsonAsync("/dirac/YuukoRequest", payload, ct);
            resp.EnsureSuccessStatusCode();

            var body    = await resp.Content.ReadAsStringAsync(ct);
            var result  = JsonSerializer.Deserialize<RequestResult>(body, YuukoJson.Options);

            return result?.Packets ?? new List<YuukoPacket>();
        }

        public Task SubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            _subs.GetOrAdd(topic, _ => new()).Add(handler);

            // Open a background WebSocket listener for this topic
            var task = Task.Run(() => ListenWebSocket(topic, _cts.Token), _cts.Token);
            lock (_wsTasks) _wsTasks.Add(task);

            return Task.CompletedTask;
        }

        public Task UnsubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            if (_subs.TryGetValue(topic, out var list))
                list.RemoveAll(h => h == handler);
            return Task.CompletedTask;
        }

        // ── WebSocket listener ────────────────────────────────────────────────

        private async Task ListenWebSocket(string topic, CancellationToken ct)
        {
            var uri = new Uri($"{_wsBase}/subscribe/{Uri.EscapeDataString(topic)}");

            while (!ct.IsCancellationRequested)
            {
                using var ws = new ClientWebSocket();
                try
                {
                    await ws.ConnectAsync(uri, ct);
                    var buffer = new byte[64 * 1024];

                    while (ws.State == WebSocketState.Open && !ct.IsCancellationRequested)
                    {
                        var result = await ws.ReceiveAsync(buffer, ct);
                        if (result.MessageType == WebSocketMessageType.Close) break;

                        var json   = Encoding.UTF8.GetString(buffer, 0, result.Count);
                        var packet = YuukoPacket.FromJson(json);
                        if (packet is null) continue;

                        if (_subs.TryGetValue(topic, out var handlers))
                            foreach (var h in handlers)
                                try   { await h(packet); }
                                catch { /* isolate */ }
                    }
                }
                catch (OperationCanceledException) { break; }
                catch
                {
                    // Back-off before reconnect
                    await Task.Delay(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                }
            }
        }

        // ── Health ────────────────────────────────────────────────────────────

        /// <summary>Returns true if the Eclipse server is reachable.</summary>
        public async Task<bool> PingAsync(CancellationToken ct = default)
        {
            try
            {
                var resp = await _http.GetAsync("/health", ct);
                return resp.IsSuccessStatusCode;
            }
            catch { return false; }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _http.Dispose();
            _cts.Dispose();
        }

        // ── Private types ─────────────────────────────────────────────────────

        private sealed class RequestResult
        {
            public List<YuukoPacket>? Packets { get; init; }
        }
    }
}

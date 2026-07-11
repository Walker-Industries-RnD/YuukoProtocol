using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{

    public interface IYuukoApi
    {
        /// <summary>Push a packet to all subscribers of <paramref name="topic"/>.</summary>
        Task PublishAsync(string topic, YuukoPacket packet, CancellationToken ct = default);

        /// <summary>Pull-style: returns all currently stored (non-ephemeral) packets on <paramref name="topic"/>.</summary>
        Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default);

        /// <summary>Register a callback that fires each time a packet arrives on <paramref name="topic"/>.</summary>
        Task SubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default);

        /// <summary>Remove a previously registered handler from <paramref name="topic"/>.</summary>
        Task UnsubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default);

        /// <summary>Publish a tombstone (delete signal) for a named packet.</summary>
        Task TombstoneAsync(string topic, string name, CancellationToken ct = default) =>
            PublishAsync(topic, YuukoPacket.Tombstone(name), ct);
    }



    public sealed class LocalBroker : IYuukoApi, IDisposable
    {
        private readonly ConcurrentDictionary<string, List<Func<YuukoPacket, Task>>> _subs  = new();
        private readonly ConcurrentDictionary<string, List<YuukoPacket>>             _store = new();
        private readonly SemaphoreSlim _lock = new(1, 1);

        public async Task PublishAsync(string topic, YuukoPacket packet, CancellationToken ct = default)
        {
            await _lock.WaitAsync(ct);
            List<Func<YuukoPacket, Task>> handlers;
            try
            {
                var store = _store.GetOrAdd(topic, _ => new());

                if (packet.IsTombstone)
                {
                    store.RemoveAll(p => p.Name == packet.Name);
                }
                else
                {
                    store.RemoveAll(p => p.Name == packet.Name);
                    if (!packet.IsEphemeral) store.Add(packet);
                }

                handlers = _subs.TryGetValue(topic, out var h) ? new(h) : new();
            }
            finally { _lock.Release(); }

            foreach (var h in handlers)
            {
                try   { await h(packet); }
                catch { /* isolate faults per handler */ }
            }
        }

        public async Task<IReadOnlyList<YuukoPacket>> RequestAsync(string topic, CancellationToken ct = default)
        {
            await _lock.WaitAsync(ct);
            try
            {
                return _store.TryGetValue(topic, out var list)
                    ? list.ToList().AsReadOnly()
                    : Array.Empty<YuukoPacket>();
            }
            finally { _lock.Release(); }
        }

        public async Task SubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            await _lock.WaitAsync(ct);
            try   { _subs.GetOrAdd(topic, _ => new()).Add(handler); }
            finally { _lock.Release(); }
        }

        public async Task UnsubscribeAsync(string topic, Func<YuukoPacket, Task> handler, CancellationToken ct = default)
        {
            await _lock.WaitAsync(ct);
            try
            {
                if (_subs.TryGetValue(topic, out var list))
                    list.RemoveAll(h => h == handler);
            }
            finally { _lock.Release(); }
        }

        public void Clear() { _subs.Clear(); _store.Clear(); }

        public void Dispose() => _lock.Dispose();
    }

}

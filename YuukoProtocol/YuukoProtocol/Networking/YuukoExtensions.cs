// YuukoExtensions.cs
// Fluent helpers for IYuukoApi
// Walker Industries R&D

using System;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{
    public static class YuukoExtensions
    {
        //Publish a UTF-8 JSON string as a Json packet.
        public static Task PublishJsonAsync(this IYuukoApi api, string topic, string name, string json, CancellationToken ct = default) =>
            api.PublishAsync(topic, YuukoPacket.FromString(name, json), ct);

        //Publish a serializable object as a Json packet.
        public static Task PublishObjectAsync<T>(this IYuukoApi api, string topic, string name, T obj, CancellationToken ct = default) =>
            api.PublishJsonAsync(topic, name, JsonSerializer.Serialize(obj, YuukoJson.Options), ct);

        //Publish an ephemeral (fire-and-forget, not stored) packet.
        public static Task PublishEphemeralAsync(this IYuukoApi api, string topic, string name, byte[] data, CancellationToken ct = default) =>
            api.PublishAsync(topic, YuukoPacket.Ephemeral(name, data), ct);

        //Try to deserialise the first stored Json packet on a topic as T.
        public static async Task<T?> RequestFirstAsync<T>(this IYuukoApi api, string topic, CancellationToken ct = default)
        {
            var packets = await api.RequestAsync(topic, ct);
            if (packets.Count == 0) return default;
            var json = Encoding.UTF8.GetString(packets[0].Data);
            return JsonSerializer.Deserialize<T>(json, YuukoJson.Options);
        }
    }
}

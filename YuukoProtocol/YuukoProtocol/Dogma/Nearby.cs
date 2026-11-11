// Nearby.cs - Finding devices you don't know (The streetpass part of the Cogitarium, which was made for the SCCN): devices on the same network find each other and join the mesh of a chunk.
//
//   await Nearby.Start();                                     // once, opens a SECOND node that lets strangers in (Your private group stays closed)
//   Cogitarium.JoinChunk("district-12");                      // from here on it's the normal Cogitarium calls, now over the nearby node
//   Cogitarium.AcceptSource(sourceFingerprint);
//
//   await Nearby.Start("nearby.identity");                    // a source keeps the same identity between runs, so others can keep accepting it
//   await Nearby.Start(null, "tcp/192.168.49.1:7447");        // a Wi-Fi Direct group: the group owner's address (or any address you know)
//   await Nearby.Start(MyTransport);                          // any link the app builds itself (Wi-Fi Aware, Bluetooth bridge...), as an IYuukoApi
//   Nearby.Stop();                                            // when you leave
//
//   // Streetpass: a card (up to 1 KB, whatever you like) is swapped with every device you connect to
//   Nearby.MyCard = Encoding.UTF8.GetBytes("Herman, likes Gaussian splats");
//   Nearby.Passed += met => Show(met.ID, met.Card, met.Times);        // met.Times is how many separate times you met
//
// How it works: Nearby opens its own transport with LAN discovery on (Zenoh multicast) and its own EclipseBroker with its own identity, away from your
// private node. Every few seconds a device announces its ID on the network, and the one with the lower ID calls the other (Only one of two dials).
// The handshake is the normal Yuuko one (Kyber-1024, Dilithium5, AES-256-GCM, forward secrecy), only without the group key, the device list
// and the TLS certificate, because a stranger has none of those. Cogitarium then runs over this node, so everything in it works the same.
//
// What a stranger can do: connect, say which chunks it is in, and send stream commands (Nothing else is answered: every command that doesn't
// start with "sccn." is denied, and nothing of your private group is on this node). A stranger can't make you show or pass on a stream:
// Cogitarium only keeps streams from sources you accepted by fingerprint, and checks every piece against the source's signature.
//
// What it does NOT do: it only finds devices on the same network (Wi-Fi/LAN or a Wi-Fi Direct group, which are networks to Zenoh; Bluetooth only if you give it a transport), the link under the handshake is not
// TLS so someone on the network can see who is talking to whom (not what), a stranger can make as many identities as it likes (So votes
// and distrust are cheap to fake, and a device you distrusted comes back with a new ID), and it only holds MaxNeighbors devices (Others are disconnected).
// A device here announces a random ID, not its name, and not the one from Identity.CreateNode.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol.Dogma
{
    public static class Nearby
    {
        //The most devices we stay connected to, the rest are disconnected
        public static int MaxNeighbors { get; set; } = 64;

        //How often we announce ourselves
        public static TimeSpan BeaconEvery { get; set; } = TimeSpan.FromSeconds(5);

        //The biggest card, and how many people we remember
        public const int MaxCardBytes = 1024;
        public const int MaxMet = 1000;

        //Someone we met (Streetpass), the card is whatever THEY said, nobody checked it. The fingerprint is the part that is checked
        public class Met
        {
            public string Fingerprint = "";
            public string ID = "";
            public byte[] Card = Array.Empty<byte>();
            public DateTime FirstMet;
            public DateTime LastMet;
            public int Times;
        }

        //Fires the first time we meet someone, and again each time we meet again later
        public static event Action<Met>? Passed;

        static Presence? Current;
        static IDisposable? Owned;               //The transport we opened (One the app gave us is the app's to close)
        static byte[] CardBytes = Array.Empty<byte>();

        public static bool IsOn => Current is not null;

        #region Create

        //Opens the nearby node and puts Cogitarium on it, call it once (A path keeps this device's identity between runs, nothing keeps a random one each time)
        //Addresses are devices to call right away, like a Wi-Fi Direct group owner, others are found by themselves
        public static async Task Start(string? IdentityPath = null, params string[] ConnectTo)
        {
            if (Current is not null) return;

            //Multicast discovery only works without TLS, so the link is plain and the handshake does the encrypting
            var Setup = new ZenohBrokerOptions { EnableTls = false, AllowPlaintextDiscovery = true, DeviceName = "nearby" };
            Setup.ConnectEndpoints.AddRange(ConnectTo);

            var Opened = ZenohBroker.Open(Setup);
            try { await Begin(Opened, IdentityPath); }
            catch { Opened.Dispose(); throw; }

            Owned = Opened;
        }

        //Any link the app made itself (Wi-Fi Aware, a Bluetooth bridge, a test), it stays the app's to close
        public static Task Start(IYuukoApi Transport, string? IdentityPath = null) =>
            Current is not null ? Task.CompletedTask : Begin(Transport, IdentityPath);

        static async Task Begin(IYuukoApi Link, string? IdentityPath)
        {
            Current = await Presence.Create(Link, MakeIdentity(IdentityPath), BeaconEvery);
            Current.Card = CardBytes;
            Current.Passed += Met => Passed?.Invoke(Met);
            Cogitarium.Attach(Current.Node);
        }

        static YuukoIdentity MakeIdentity(string? Path)
        {
            if (Path is null) return YuukoIdentity.Create(NewID());
            if (File.Exists(Path)) return YuukoIdentity.Import(File.ReadAllBytes(Path));

            var Made = YuukoIdentity.Create(NewID());
            Made.Save(Path);
            return Made;
        }

        internal static string NewID() => "near-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();

        #endregion

        #region Read

        //The ID others see (Not your device name)
        public static string MyID => Current?.Node.ClientId ?? throw new InvalidOperationException("Call Nearby.Start() first.");

        //The devices connected to us right now
        public static List<string> Neighbors => Current?.Node.ConnectedPeers.ToList() ?? new();

        //Everyone we met, newest first
        public static List<Met> People => Current?.Met.Values.OrderByDescending(m => m.LastMet).ToList() ?? new();

        #endregion

        #region Update

        //What we hand to everyone we connect to from now on (Up to 1 KB)
        public static byte[] MyCard
        {
            get => CardBytes;
            set
            {
                if (value is null || value.Length > MaxCardBytes) throw new ArgumentException($"A card is at most {MaxCardBytes} bytes.");
                CardBytes = value;
                if (Current is not null) Current.Card = value;
            }
        }

        #endregion

        #region Delete

        public static void Stop()
        {
            Cogitarium.Reset(true);
            Current?.Dispose();
            Owned?.Dispose();
            Current = null;
            Owned = null;
        }

        //Forget someone we met
        public static void Forget(string Fingerprint) => Current?.Met.TryRemove(Fingerprint, out _);

        #endregion


        //One per nearby node
        internal sealed class Presence : IDisposable
        {
            const string BeaconTopic = "yuuko/nearby/presence";
            const int IDLength = 21;                            //near- and 16 hex characters
            static readonly TimeSpan RetryAfter = TimeSpan.FromSeconds(20);

            public readonly EclipseBroker Node;
            readonly IYuukoApi Transport;
            readonly CancellationTokenSource Stopping = new();
            readonly ConcurrentDictionary<string, DateTime> Tried = new();      //Who we called and when, so a beacon doesn't make us call them again at once
            readonly SemaphoreSlim Dialing = new(8);
            static readonly CommandOptions Quick = new() { Timeout = TimeSpan.FromSeconds(3), Retries = 0 };
            static readonly TimeSpan MetAgain = TimeSpan.FromMinutes(10);        //Meeting again within this isn't a new time

            public readonly ConcurrentDictionary<string, Met> Met = new();
            public byte[] Card = Array.Empty<byte>();
            public event Action<Met>? Passed;
            readonly Func<YuukoPacket, Task> Listener;
            int _Disposed;

            Presence(IYuukoApi Transport, EclipseBroker Node)
            {
                this.Transport = Transport;
                this.Node = Node;
                Listener = Heard;
            }

            //What a stranger is allowed to do on this node (And what it isn't)
            internal static EclipseBrokerOptions OpenOptions()
            {
                var Options = new EclipseBrokerOptions();

                Options.DataTopic = "yuuko/nearby/data";
                Options.Handshake.Topic = "yuuko/nearby/handshake";

                //A piece and what comes with it, nothing bigger
                Options.MaxCommandBytes = Cogitarium.MaxSegmentBytes + 64 * 1024;
                Options.MaxConcurrentCommands = 32;

                //Only the stream commands, everything else is denied before it runs (Pairing and group changes aren't offered here anyway)
                Options.CommandAuthorizer = (Peer, Command) => Command.StartsWith("sccn.", StringComparison.Ordinal);

                return Options;
            }

            public static async Task<Presence> Create(IYuukoApi Transport, YuukoIdentity Me, TimeSpan Every)
            {
                var Node = EclipseBroker.Create(Transport, Me, OpenOptions());
                var Made = new Presence(Transport, Node);

                try
                {
                    await Node.StartAsync();
                    await Transport.SubscribeAsync(BeaconTopic, Made.Listener);

                    Node.On("sccn.card", (c, _) => Task.FromResult(Made.HandleCard(c)));
                    Node.PeerConnected += Made.OnConnected;
                    _ = Task.Run(() => Made.Announce(Every));
                    return Made;
                }
                catch
                {
                    Made.Dispose();
                    throw;
                }
            }

            //Tell the network we're here
            async Task Announce(TimeSpan Every)
            {
                var Body = Encoding.UTF8.GetBytes(new JsonObject { ["id"] = Node.ClientId }.ToJsonString());

                while (!Stopping.IsCancellationRequested)
                {
                    try { await Transport.PublishAsync(BeaconTopic, YuukoPacket.Ephemeral("beacon", Body), Stopping.Token); }
                    catch (OperationCanceledException) { return; }
                    catch { }

                    try { await Task.Delay(Every, Stopping.Token); }
                    catch (OperationCanceledException) { return; }
                }
            }

            //Someone announced themselves, if we should call them we do (Only the one with the lower ID does)
            Task Heard(YuukoPacket Packet)
            {
                string Id;
                try { Id = JsonNode.Parse(Packet.Data)?["id"]?.GetValue<string>() ?? ""; }
                catch { return Task.CompletedTask; }

                if (Id.Length != IDLength || !Id.StartsWith("near-", StringComparison.Ordinal) || !Id.Skip(5).All(Uri.IsHexDigit)) return Task.CompletedTask;
                if (string.CompareOrdinal(Node.ClientId, Id) >= 0) return Task.CompletedTask;
                if (Node.IsConnected(Id) || Node.ConnectedPeers.Count >= MaxNeighbors || Stopping.IsCancellationRequested) return Task.CompletedTask;

                var Now = DateTime.UtcNow;
                if (Tried.TryGetValue(Id, out var Last) && Now - Last < RetryAfter) return Task.CompletedTask;
                Tried[Id] = Now;
                if (Tried.Count > 1000) foreach (var Old in Tried.Where(t => Now - t.Value > RetryAfter).Select(t => t.Key).ToList()) Tried.TryRemove(Old, out _);

                _ = Task.Run(() => Call(Id));
                return Task.CompletedTask;
            }

            async Task Call(string Id)
            {
                try
                {
                    await Dialing.WaitAsync(Stopping.Token);
                    try { await Node.PingAsync(Id, Stopping.Token); }
                    finally { Dialing.Release(); }
                }
                catch { }
            }

            //Too many neighbors, the newest one goes. Otherwise we hand them our card
            void OnConnected(PeerInfo Peer)
            {
                if (Node.ConnectedPeers.Count > MaxNeighbors)
                {
                    _ = Node.KickAsync(Peer.Id, false, "too many nearby devices");
                    return;
                }

                _ = Task.Run(async () =>
                {
                    try { await Node.SendCommandAsync(Peer.Id, "sccn.card", Encoding.UTF8.GetBytes(new JsonObject { ["card"] = Convert.ToBase64String(Card) }.ToJsonString()), Quick); }
                    catch { }
                });
            }

            //Someone hands us their card
            CommandResult HandleCard(CommandContext Context)
            {
                if (Context.Payload.Length > MaxCardBytes * 2) return CommandResult.Error("too big");

                byte[] Given;
                try { Given = Convert.FromBase64String((string?)JsonNode.Parse(Context.Payload)?["card"] ?? ""); }
                catch (Exception ex) when (ex is JsonException or FormatException or InvalidCastException) { return CommandResult.Error("malformed"); }
                if (Given.Length > MaxCardBytes) return CommandResult.Error("too big");

                //Who they are comes from the handshake, not from what they say
                var Fingerprint = Node.Peers.FirstOrDefault(p => p.Id == Context.FromId)?.Fingerprint;
                if (Fingerprint is null) return CommandResult.Denied("no session");

                var Now = DateTime.UtcNow;
                bool Again = false;

                var Seen = Met.AddOrUpdate(Fingerprint,
                    _ => { Again = true; return new Met { Fingerprint = Fingerprint, ID = Context.FromId, Card = Given, FirstMet = Now, LastMet = Now, Times = 1 }; },
                    (_, Old) =>
                    {
                        if (Now - Old.LastMet > MetAgain) { Old.Times++; Again = true; }
                        Old.LastMet = Now; Old.ID = Context.FromId; Old.Card = Given;
                        return Old;
                    });

                //The ones we saw longest ago go first
                while (Met.Count > MaxMet && Met.OrderBy(m => m.Value.LastMet).FirstOrDefault().Key is { } Oldest) Met.TryRemove(Oldest, out _);

                if (Again) Passed?.Invoke(Seen);
                return CommandResult.Ok();
            }

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _Disposed, 1) != 0) return;

                Stopping.Cancel();
                Node.PeerConnected -= OnConnected;
                Node.Off("sccn.card");
                try { Transport.UnsubscribeAsync(BeaconTopic, Listener).GetAwaiter().GetResult(); } catch { }
                Node.Dispose();
            }
        }
    }
}

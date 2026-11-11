// YuukoCommands.cs
// The public types of the encrypted command channel.
//
//   receiver:  node.On("Timer.Start", async (ctx, ct) => { ...; return CommandResult.Ok(); });
//   sender:    var ack = await node.SendCommandAsync("phone", "Timer.Start", payload);
//              if (ack.IsOk) ... else Console.WriteLine(ack.Status + " " + ack.Message);
//
// A command is sent over a peer's encrypted session, run by the handler registered under its
// name on the other device, and answered with an ack saying how it went.
//
// Walker Industries R&D — YuukoProtocol

using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace YuukoProtocol
{
    /// <summary>
    /// How a command ended. Values below 100 come from the other device (its handler, or its policy);
    /// 100 and up are produced locally when no answer came back at all.
    /// </summary>
    public enum AckStatus
    {
        Ok = 0,
        /// <summary>The handler ran and failed, or the request was malformed.</summary>
        Error = 1,
        /// <summary>The other device's authorizer refused this command from us.</summary>
        Denied = 2,
        /// <summary>The other device has no handler registered under that name.</summary>
        UnknownCommand = 3,
        /// <summary>The other device was already running as many commands as it allows.</summary>
        Busy = 4,

        /// <summary>No answer arrived in time. The command MAY still have run; see <see cref="CommandOptions.Retries"/>.</summary>
        TimedOut = 100,
        /// <summary>No session could be established (device offline, not trusted, wrong key, banned...).</summary>
        Unreachable = 101,
    }

    /// <summary>The answer to a command.</summary>
    public sealed record CommandAck(AckStatus Status, byte[] Result, string? Message, TimeSpan Elapsed)
    {
        public bool IsOk => Status == AckStatus.Ok;

        /// <summary>True if the other device produced this answer (as opposed to a local timeout / unreachable).</summary>
        public bool IsFromPeer => (int)Status < 100;

        public string ResultAsString() => Encoding.UTF8.GetString(Result);

        public override string ToString() =>
            $"{Status}{(Message is null ? "" : ": " + Message)} ({Elapsed.TotalMilliseconds:F0} ms)";
    }

    /// <summary>What a command handler is told about the command it is running.</summary>
    public sealed record CommandContext(string FromId, string Name, byte[] Payload, string RequestId,
        string? OriginId = null, string? ChangeId = null)
    {
        /// <summary>
        /// The device that started this command. Same as <see cref="FromId"/> unless it was relayed
        /// (<see cref="EclipseBroker.BroadcastAsync"/>), in which case <see cref="FromId"/> is the device that handed
        /// it to us and this is the device that started it. That is checked: the broadcast carries the origin's signature, which
        /// was verified against a key this device trusts for that origin before the handler ran.
        /// </summary>
        public string Origin => OriginId ?? FromId;

        /// <summary>True if the command reached us through a relay (or a broadcast), not straight from a single sender.</summary>
        public bool IsBroadcast => ChangeId is not null;

        public string PayloadAsString() => Encoding.UTF8.GetString(Payload);
    }

    /// <summary>
    /// What <see cref="EclipseBroker.BroadcastAsync"/> did. <see cref="Acks"/> holds one ack per device we handed it to
    /// DIRECTLY. Devices further along were reached by those devices relaying it; we do not hear from them.
    /// </summary>
    public sealed record BroadcastResult(string ChangeId, IReadOnlyDictionary<string, CommandAck> Acks)
    {
        /// <summary>True if every directly connected device accepted it (also true when there was nobody to tell).</summary>
        public bool AllAccepted => Acks.Values.All(a => a.IsOk);
    }

    /// <summary>What a command handler returns.</summary>
    public sealed record CommandResult(AckStatus Status, byte[] Data, string? Message)
    {
        public static CommandResult Ok(byte[]? data = null) => new(AckStatus.Ok, data ?? Array.Empty<byte>(), null);
        public static CommandResult Ok(string text) => Ok(Encoding.UTF8.GetBytes(text));
        public static CommandResult Error(string message) => new(AckStatus.Error, Array.Empty<byte>(), message);
        public static CommandResult Denied(string message = "denied") => new(AckStatus.Denied, Array.Empty<byte>(), message);
    }

    /// <summary>
    /// A command implementation. It runs on a background thread, may take a while (up to
    /// <see cref="EclipseBrokerOptions.CommandHandlerTimeout"/>), and may throw: a thrown exception
    /// becomes an <see cref="AckStatus.Error"/> ack that names only the exception type.
    /// </summary>
    public delegate Task<CommandResult> CommandHandler(CommandContext context, CancellationToken ct);

    /// <summary>Per-call overrides for <see cref="EclipseBroker.SendCommandAsync"/>. Null means "use the broker default".</summary>
    public sealed class CommandOptions
    {
        /// <summary>How long to wait for the ack on each attempt.</summary>
        public TimeSpan? Timeout { get; set; }

        /// <summary>
        /// Extra attempts after a timeout. Retries reuse the same request id, so the other device
        /// runs the command at most once and simply repeats its answer.
        /// </summary>
        public int? Retries { get; set; }
    }

    /// <summary>A connected peer, as seen by this device.</summary>
    public sealed record PeerInfo(
        string Id,
        string Fingerprint,
        DateTimeOffset ConnectedUtc,
        DateTimeOffset LastSeenUtc,
        bool IsOnline);
}

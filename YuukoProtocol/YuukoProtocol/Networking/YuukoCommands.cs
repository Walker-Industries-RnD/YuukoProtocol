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
    // What was thrown because the other device's message was not shaped right (as opposed to a bug of ours)
    internal static class BadInput
    {
        public static bool Is(Exception e) =>
            e is System.Text.Json.JsonException or FormatException or InvalidCastException or InvalidOperationException or ArgumentException or OverflowException;
    }

    //How a command ended. Values below 100 come from the other device (its handler, or its policy);
    //100 and up are produced locally when no answer came back at all.
    public enum AckStatus
    {
        Ok = 0,
        //The handler ran and failed, or the request was malformed.
        Error = 1,
        //The other device's authorizer refused this command from us.
        Denied = 2,
        //The other device has no handler registered under that name.
        UnknownCommand = 3,
        //The other device was already running as many commands as it allows.
        Busy = 4,

        //No answer arrived in time. The command MAY still have run; see Retries.
        TimedOut = 100,
        //No session could be established (device offline, not trusted, wrong key, banned...).
        Unreachable = 101,
    }

    //The answer to a command.
    public sealed record CommandAck(AckStatus Status, byte[] Result, string? Message, TimeSpan Elapsed)
    {
        public bool IsOk => Status == AckStatus.Ok;

        //True if the other device produced this answer (as opposed to a local timeout / unreachable).
        public bool IsFromPeer => (int)Status < 100;

        public string ResultAsString() => Encoding.UTF8.GetString(Result);

        public override string ToString() =>
            $"{Status}{(Message is null ? "" : ": " + Message)} ({Elapsed.TotalMilliseconds:F0} ms)";
    }

    //What a command handler is told about the command it is running.
    public sealed record CommandContext(string FromId, string Name, byte[] Payload, string RequestId,
        string? OriginId = null, string? ChangeId = null)
    {
        //The device that started this command. Same as FromId unless it was relayed
        //(BroadcastAsync), in which case FromId is the device that handed
        //it to us and this is the device that started it. That is checked: the broadcast carries the origin's signature, which
        //was verified against a key this device trusts for that origin before the handler ran.
        public string Origin => OriginId ?? FromId;

        //True if the command reached us through a relay (or a broadcast), not straight from a single sender.
        public bool IsBroadcast => ChangeId is not null;

        public string PayloadAsString() => Encoding.UTF8.GetString(Payload);
    }

    //What BroadcastAsync did. Acks holds one ack per device we handed it to
    //DIRECTLY. Devices further along were reached by those devices relaying it; we do not hear from them.
    public sealed record BroadcastResult(string ChangeId, IReadOnlyDictionary<string, CommandAck> Acks)
    {
        //True if every directly connected device accepted it (also true when there was nobody to tell).
        public bool AllAccepted => Acks.Values.All(a => a.IsOk);
    }

    //What a command handler returns.
    public sealed record CommandResult(AckStatus Status, byte[] Data, string? Message)
    {
        public static CommandResult Ok(byte[]? data = null) => new(AckStatus.Ok, data ?? Array.Empty<byte>(), null);
        public static CommandResult Ok(string text) => Ok(Encoding.UTF8.GetBytes(text));
        public static CommandResult Error(string message) => new(AckStatus.Error, Array.Empty<byte>(), message);
        public static CommandResult Denied(string message = "denied") => new(AckStatus.Denied, Array.Empty<byte>(), message);
    }

    //A command implementation. It runs on a background thread, may take a while (up to
    //CommandHandlerTimeout), and may throw: a thrown exception
    //becomes an Error ack that names only the exception type.
    public delegate Task<CommandResult> CommandHandler(CommandContext context, CancellationToken ct);

    //Per-call overrides for SendCommandAsync. Null means "use the broker default".
    public sealed class CommandOptions
    {
        //How long to wait for the ack on each attempt.
        public TimeSpan? Timeout { get; set; }

        //Extra attempts after a timeout. Retries reuse the same request id, so the other device
        //runs the command at most once and simply repeats its answer.
        public int? Retries { get; set; }
    }

    //A connected peer, as seen by this device.
    public sealed record PeerInfo(
        string Id,
        string Fingerprint,
        DateTimeOffset ConnectedUtc,
        DateTimeOffset LastSeenUtc,
        bool IsOnline);
}

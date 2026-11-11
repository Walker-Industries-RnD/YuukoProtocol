// OpTransform.cs - DOGMA II: Operational Transformation for plain text.
//
// The idea in one paragraph: two devices edit the same text at the same time, each starting from the same version. Each edit is an
// OPERATION ("keep 5 characters, insert 'hi', delete 3, keep the rest"). To merge them, each device TRANSFORMS the other's operation
// so it still means the same thing after its own edit has already happened. Then both devices end up with the same text.
//
// This file is the algorithm only, with no networking:
//   TextOperation   one edit (retain / insert / delete), with Apply, Compose, Transform, Invert, and a JSON form
//   OtServer        the one authority that puts everyone's edits in a single order (the document's owner)
//   OtClient        what every other device runs: sends its edits, and transforms incoming ones against what it has not confirmed yet
//   OpTransform     the same operations as plain static helpers
// The network layer (who is the server, how operations travel) is OtSession in OtSession.cs.
//
// This follows the well-known ot.js design: it needs a SINGLE ordering authority (the server), which is why a document has an owner.
// Positions count UTF-16 code units, like .NET strings. An emoji is TWO units, and JSON cannot carry half of one, so an edit that would
// cut one in half (or insert half of one) is REFUSED with an OtException instead of being allowed to corrupt the text on its way to
// the other devices. Edit by whole characters; TextOperation.FromDiff already does.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;

namespace YuukoProtocol.Dogma
{
    //The operation was malformed, did not fit the text it was applied to, or could not be combined with another.
    public sealed class OtException : Exception
    {
        public OtException(string message) : base(message) { }
    }

    //The client is too far behind for the server to catch it up edit by edit: it must reload the whole text.
    internal sealed class OtResyncRequiredException : Exception
    {
        public OtResyncRequiredException(string message) : base(message) { }
    }

    internal enum OpKind { Retain, Insert, Delete }

    internal readonly record struct Component(OpKind Kind, int N, string? Text)
    {
        public static Component Retain(int n) => new(OpKind.Retain, n, null);
        public static Component Insert(string s) => new(OpKind.Insert, s.Length, s);
        public static Component Delete(int n) => new(OpKind.Delete, n, null);
    }

    //One edit of a text: a list of "keep N characters", "insert this text" and "delete N characters" that covers the whole text it applies to.
    internal sealed class TextOperation : IEquatable<TextOperation>
    {
        //Most components one operation may have (a limit for operations that arrive from the network).
        public const int MaxComponents = 50_000;

        //Most characters one operation may carry or cover.
        public const int MaxLength = 4_000_000;

        private readonly List<Component> _ops = new();

        //The length the text must have for this operation to apply to it.
        public int BaseLength { get; private set; }

        //The length of the text after this operation.
        public int TargetLength { get; private set; }

        internal IReadOnlyList<Component> Components => _ops;

        //True if applying it changes nothing.
        public bool IsNoop => _ops.Count == 0 || (_ops.Count == 1 && _ops[0].Kind == OpKind.Retain);

        // ── building ─────────────────────────────────────────────────────────────

        //Keep the next n characters as they are.
        public TextOperation Retain(int n)
        {
            if (n < 0) throw new ArgumentOutOfRangeException(nameof(n));
            if (n == 0) return this;
            Grow(n, n);
            if (_ops.Count > 0 && _ops[^1].Kind == OpKind.Retain) _ops[^1] = Component.Retain(_ops[^1].N + n);
            else _ops.Add(Component.Retain(n));
            return this;
        }

        //Insert text here.
        public TextOperation Insert(string text)
        {
            if (text is null) throw new ArgumentNullException(nameof(text));
            if (text.Length == 0) return this;
            if (HasUnpairedSurrogate(text)) throw new OtException("The text contains half of an emoji (an unpaired surrogate), which cannot be sent. Insert whole characters.");
            Grow(0, text.Length);

            if (_ops.Count > 0 && _ops[^1].Kind == OpKind.Insert)
                _ops[^1] = Component.Insert(_ops[^1].Text + text);
            else if (_ops.Count > 0 && _ops[^1].Kind == OpKind.Delete)
            {
                // Always write "insert" before "delete" at the same place, so equal edits have one canonical form.
                if (_ops.Count >= 2 && _ops[^2].Kind == OpKind.Insert)
                    _ops[^2] = Component.Insert(_ops[^2].Text + text);
                else
                    _ops.Insert(_ops.Count - 1, Component.Insert(text));
            }
            else _ops.Add(Component.Insert(text));
            return this;
        }

        //Delete the next n characters.
        public TextOperation Delete(int n)
        {
            if (n < 0) throw new ArgumentOutOfRangeException(nameof(n));
            if (n == 0) return this;
            Grow(n, 0);
            if (_ops.Count > 0 && _ops[^1].Kind == OpKind.Delete) _ops[^1] = Component.Delete(_ops[^1].N + n);
            else _ops.Add(Component.Delete(n));
            return this;
        }

        private void Grow(int baseBy, int targetBy)
        {
            if (_ops.Count >= MaxComponents) throw new OtException("The operation has too many parts.");
            long b = (long)BaseLength + baseBy, t = (long)TargetLength + targetBy;
            if (b > MaxLength || t > MaxLength) throw new OtException("The operation is too long.");
            BaseLength = (int)b;
            TargetLength = (int)t;
        }

        // ── using ────────────────────────────────────────────────────────────────

        //The text after the edit. document must be exactly BaseLength characters long.
        public string Apply(string document)
        {
            if (document is null) throw new ArgumentNullException(nameof(document));
            if (document.Length != BaseLength)
                throw new OtException($"The operation expects a text of {BaseLength} characters, but the text has {document.Length}.");

            var sb = new StringBuilder(TargetLength);
            var joins = new List<int>();   // where one part ends and the next begins, in the new text
            int at = 0;
            foreach (var c in _ops)
            {
                switch (c.Kind)
                {
                    case OpKind.Retain: sb.Append(document, at, c.N); at += c.N; break;
                    case OpKind.Insert: sb.Append(c.Text); break;
                    case OpKind.Delete: at += c.N; break;
                }
                joins.Add(sb.Length);
            }

            // An edit must not leave half an emoji at a seam (a retain that stops inside a pair, a delete that removes one half...).
            foreach (int j in joins)
            {
                bool endsWithHigh = j > 0 && char.IsHighSurrogate(sb[j - 1]);
                bool startsWithLow = j < sb.Length && char.IsLowSurrogate(sb[j]);
                if (endsWithHigh != startsWithLow)
                    throw new OtException("The edit would cut a character (an emoji) in half.");
            }
            return sb.ToString();
        }

        //The edit that undoes this one. document is the text this operation applies to (the text BEFORE it).
        public TextOperation Invert(string document)
        {
            if (document.Length != BaseLength) throw new OtException("The text does not match this operation.");
            var inverse = new TextOperation();
            int at = 0;
            foreach (var c in _ops)
            {
                switch (c.Kind)
                {
                    case OpKind.Retain: inverse.Retain(c.N); at += c.N; break;
                    case OpKind.Insert: inverse.Delete(c.N); break;
                    case OpKind.Delete: inverse.Insert(document.Substring(at, c.N)); at += c.N; break;
                }
            }
            return inverse;
        }

        //One edit that does what a does and then what b does.
        public static TextOperation Compose(TextOperation a, TextOperation b)
        {
            if (a.TargetLength != b.BaseLength)
                throw new OtException("Cannot compose: the first operation must end with the length the second one starts from.");

            var result = new TextOperation();
            var A = a._ops; var B = b._ops;
            int i1 = 0, i2 = 0;
            Component? c1 = Next(A, ref i1), c2 = Next(B, ref i2);

            while (c1 is not null || c2 is not null)
            {
                if (c1 is { Kind: OpKind.Delete } del1) { result.Delete(del1.N); c1 = Next(A, ref i1); continue; }
                if (c2 is { Kind: OpKind.Insert } ins2) { result.Insert(ins2.Text!); c2 = Next(B, ref i2); continue; }
                if (c1 is null) throw new OtException("Cannot compose: the first operation is too short.");
                if (c2 is null) throw new OtException("Cannot compose: the first operation is too long.");

                var x = c1.Value; var y = c2.Value;
                switch (x.Kind, y.Kind)
                {
                    case (OpKind.Retain, OpKind.Retain):
                        if (x.N > y.N) { result.Retain(y.N); c1 = Component.Retain(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { result.Retain(x.N); c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { result.Retain(x.N); c2 = Component.Retain(y.N - x.N); c1 = Next(A, ref i1); }
                        break;
                    case (OpKind.Insert, OpKind.Delete):
                        if (x.N > y.N) { c1 = Component.Insert(x.Text![y.N..]); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { c2 = Component.Delete(y.N - x.N); c1 = Next(A, ref i1); }
                        break;
                    case (OpKind.Insert, OpKind.Retain):
                        if (x.N > y.N) { result.Insert(x.Text![..y.N]); c1 = Component.Insert(x.Text![y.N..]); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { result.Insert(x.Text!); c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { result.Insert(x.Text!); c2 = Component.Retain(y.N - x.N); c1 = Next(A, ref i1); }
                        break;
                    case (OpKind.Retain, OpKind.Delete):
                        if (x.N > y.N) { result.Delete(y.N); c1 = Component.Retain(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { result.Delete(y.N); c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { result.Delete(x.N); c2 = Component.Delete(y.N - x.N); c1 = Next(A, ref i1); }
                        break;
                    default:
                        throw new OtException("Cannot compose these operations.");
                }
            }
            return result;
        }

        //Both operations start from the same text. Returns (a', b') such that applying a then b' gives the same text as
        //Applying b then a'. When both insert at the same place, a's text comes first.
        public static (TextOperation A1, TextOperation B1) Transform(TextOperation a, TextOperation b)
        {
            if (a.BaseLength != b.BaseLength) throw new OtException("Both operations have to start from the same text length.");

            var a1 = new TextOperation(); var b1 = new TextOperation();
            var A = a._ops; var B = b._ops;
            int i1 = 0, i2 = 0;
            Component? c1 = Next(A, ref i1), c2 = Next(B, ref i2);

            while (c1 is not null || c2 is not null)
            {
                if (c1 is { Kind: OpKind.Insert } ins1) { a1.Insert(ins1.Text!); b1.Retain(ins1.N); c1 = Next(A, ref i1); continue; }
                if (c2 is { Kind: OpKind.Insert } ins2) { a1.Retain(ins2.N); b1.Insert(ins2.Text!); c2 = Next(B, ref i2); continue; }
                if (c1 is null) throw new OtException("Cannot transform: the first operation is too short.");
                if (c2 is null) throw new OtException("Cannot transform: the first operation is too long.");

                var x = c1.Value; var y = c2.Value;
                int min;
                switch (x.Kind, y.Kind)
                {
                    case (OpKind.Retain, OpKind.Retain):
                        if (x.N > y.N) { min = y.N; c1 = Component.Retain(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { min = x.N; c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { min = x.N; c2 = Component.Retain(y.N - x.N); c1 = Next(A, ref i1); }
                        a1.Retain(min); b1.Retain(min);
                        break;
                    case (OpKind.Delete, OpKind.Delete):
                        // both removed the same characters: nothing left to do for either
                        if (x.N > y.N) { c1 = Component.Delete(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { c2 = Component.Delete(y.N - x.N); c1 = Next(A, ref i1); }
                        break;
                    case (OpKind.Delete, OpKind.Retain):
                        if (x.N > y.N) { min = y.N; c1 = Component.Delete(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { min = x.N; c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { min = x.N; c2 = Component.Retain(y.N - x.N); c1 = Next(A, ref i1); }
                        a1.Delete(min);
                        break;
                    case (OpKind.Retain, OpKind.Delete):
                        if (x.N > y.N) { min = y.N; c1 = Component.Retain(x.N - y.N); c2 = Next(B, ref i2); }
                        else if (x.N == y.N) { min = x.N; c1 = Next(A, ref i1); c2 = Next(B, ref i2); }
                        else { min = x.N; c2 = Component.Delete(y.N - x.N); c1 = Next(A, ref i1); }
                        b1.Delete(min);
                        break;
                    default:
                        throw new OtException("Cannot transform these operations.");
                }
            }
            return (a1, b1);
        }

        //The smallest single edit that turns before into after (keep the common start and end, replace the middle). Handy when all you have is the new text of a text box.
        public static TextOperation FromDiff(string before, string after)
        {
            if (before is null) throw new ArgumentNullException(nameof(before));
            if (after is null) throw new ArgumentNullException(nameof(after));
            int start = 0, max = Math.Min(before.Length, after.Length);
            while (start < max && before[start] == after[start]) start++;
            int endB = before.Length, endA = after.Length;
            while (endB > start && endA > start && before[endB - 1] == after[endA - 1]) { endB--; endA--; }

            // Never cut an emoji in half: if the shared start or end stops inside a pair, give that pair to the changed middle.
            if (start > 0 && char.IsHighSurrogate(before[start - 1])) start--;
            if (endB < before.Length && char.IsLowSurrogate(before[endB])) { endB++; endA++; }

            var op = new TextOperation().Retain(start);
            op.Insert(after.Substring(start, endA - start));
            op.Delete(endB - start);
            op.Retain(before.Length - endB);
            return op;
        }

        private static Component? Next(List<Component> list, ref int i) => i < list.Count ? list[i++] : null;

        //True if the text has a surrogate half with no partner (it cannot be written as JSON).
        public static bool HasUnpairedSurrogate(string text)
        {
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (char.IsHighSurrogate(c))
                {
                    if (i + 1 < text.Length && char.IsLowSurrogate(text[i + 1])) i++;
                    else return true;
                }
                else if (char.IsLowSurrogate(c)) return true;
            }
            return false;
        }

        // ── a form that travels: [5, "hi", -3, 12] = keep 5, insert "hi", delete 3, keep 12 ──────────

        //The operation as JSON: positive numbers keep, negative numbers delete, strings insert.
        public string ToJson()
        {
            using var ms = new System.IO.MemoryStream();
            using (var w = new Utf8JsonWriter(ms))
            {
                w.WriteStartArray();
                foreach (var c in _ops)
                {
                    switch (c.Kind)
                    {
                        case OpKind.Retain: w.WriteNumberValue(c.N); break;
                        case OpKind.Insert: w.WriteStringValue(c.Text); break;
                        case OpKind.Delete: w.WriteNumberValue(-c.N); break;
                    }
                }
                w.WriteEndArray();
            }
            return Encoding.UTF8.GetString(ms.ToArray());
        }

        //Reads an operation, refusing anything malformed or oversized (this is for text that arrives from the network).
        public static TextOperation FromJson(string json)
        {
            if (!TryFromJson(json, out var op, out var error)) throw new OtException(error!);
            return op!;
        }

        public static bool TryFromJson(string? json, out TextOperation? operation, out string? error)
        {
            operation = null; error = null;
            try
            {
                if (string.IsNullOrEmpty(json)) { error = "The operation is empty."; return false; }
                using var doc = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
                if (doc.RootElement.ValueKind != JsonValueKind.Array) { error = "An operation is a list."; return false; }
                if (doc.RootElement.GetArrayLength() > MaxComponents) { error = "The operation has too many parts."; return false; }

                var op = new TextOperation();
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    if (el.ValueKind == JsonValueKind.String) op.Insert(el.GetString()!);
                    else if (el.ValueKind == JsonValueKind.Number && el.TryGetInt32(out int n))
                    {
                        if (n > 0) op.Retain(n);
                        else if (n < 0) op.Delete(checked(-n));
                        else { error = "An operation cannot contain 0."; return false; }
                    }
                    else { error = "An operation holds only numbers and text."; return false; }
                }
                operation = op;
                return true;
            }
            catch (Exception e) when (e is JsonException or OtException or OverflowException or ArgumentException or InvalidOperationException)
            {
                error = e is OtException ? e.Message : "That is not a valid operation.";
                return false;
            }
        }

        // ── equality ─────────────────────────────────────────────────────────────

        public bool Equals(TextOperation? other) => other is not null && _ops.SequenceEqual(other._ops);
        public override bool Equals(object? obj) => Equals(obj as TextOperation);
        public override int GetHashCode()
        {
            var h = new HashCode();
            foreach (var c in _ops) h.Add(c);
            return h.ToHashCode();
        }
        public override string ToString() => ToJson();
    }

    //The one authority for a document: it receives everyone's edits, puts them in a single order, and says what each one turned into.
    //Not thread-safe by itself: the network layer holds a lock around it.
    internal sealed class OtServer
    {
        private readonly List<TextOperation> _history = new();
        private readonly int _historyLimit;
        private int _baseRevision;

        public string Document { get; private set; }

        //How many edits the document has had (the revision a new edit should be based on).
        public int Revision => _baseRevision + _history.Count;

        //The oldest revision a client can still be caught up from. Older clients must reload the whole text.
        public int OldestRevision => _baseRevision;

        public OtServer(string document = "", int historyLimit = 50_000, int startRevision = 0)
        {
            Document = document ?? throw new ArgumentNullException(nameof(document));
            if (historyLimit < 1) throw new ArgumentOutOfRangeException(nameof(historyLimit));
            _historyLimit = historyLimit;
            _baseRevision = startRevision;
        }

        //A client sends an edit it made while looking at revision revision. It is transformed over everything that
        //Happened since, applied, stored, and returned: send THAT to the other clients.
        public TextOperation Receive(int revision, TextOperation operation)
        {
            if (revision > Revision) throw new OtException("That revision does not exist yet.");
            if (revision < _baseRevision) throw new OtResyncRequiredException("That client is too far behind: it has to reload the text.");

            var op = operation;
            for (int i = revision - _baseRevision; i < _history.Count; i++)
                op = TextOperation.Transform(op, _history[i]).A1;

            var next = op.Apply(Document);   // throws OtException if the edit does not fit
            Document = next;
            _history.Add(op);
            if (_history.Count > _historyLimit)
            {
                int drop = _history.Count - _historyLimit;
                _history.RemoveRange(0, drop);
                _baseRevision += drop;
            }
            return op;
        }

        //The edits from revision up to now, to catch a client up. Throws OtResyncRequiredException if they are no longer kept.
        public IReadOnlyList<TextOperation> OperationsFrom(int revision)
        {
            if (revision > Revision || revision < 0) throw new OtException("That revision does not exist.");
            if (revision < _baseRevision) throw new OtResyncRequiredException("Those edits are no longer kept.");
            return _history.Skip(revision - _baseRevision).ToList();
        }
    }

    //What every device other than the server runs. You edit Text through ApplyClient; edits from the server
    //Come in through ApplyServer and ServerAck. It keeps at most one edit "in flight" to the server, and
    //Folds everything you type meanwhile into one buffered edit, so the server only ever sees edits in order.
    //Not thread-safe by itself: the network layer holds a lock around it.
    internal sealed class OtClient
    {
        private enum State { Synchronized, AwaitingConfirm, AwaitingWithBuffer }

        private State _state = State.Synchronized;
        private TextOperation? _outstanding;
        private TextOperation? _buffer;

        //The text as this device sees it: the server's text plus this device's own unconfirmed edits.
        public string Text { get; private set; }

        //The newest server revision this device has taken in.
        public int Revision { get; private set; }

        //Called when an edit must be sent to the server: (the revision it is based on, the edit). Send it again, unchanged, if you do not hear back.
        public Action<int, TextOperation>? Send { get; set; }

        public OtClient(string text, int revision)
        {
            Text = text ?? throw new ArgumentNullException(nameof(text));
            Revision = revision;
        }

        //True while an edit of this device has not been confirmed by the server yet.
        public bool HasPending => _state != State.Synchronized;

        //The edit currently in flight to the server, in the form that fits the server's text at Revision (null when none). Use THIS
        //To send it again if the first send may have been lost: the edit has been transformed over everything the server sent since it was
        //First sent, so sending it again with its old revision would transform it a second time and corrupt the text.
        public (int Revision, TextOperation Operation)? Outstanding => _outstanding is null ? null : (Revision, _outstanding);

        //You edited the text. operation must start from the current Text.
        public void ApplyClient(TextOperation operation)
        {
            Text = operation.Apply(Text);   // throws (and changes nothing) if it does not fit

            switch (_state)
            {
                case State.Synchronized:
                    _outstanding = operation;
                    _state = State.AwaitingConfirm;
                    Send?.Invoke(Revision, operation);
                    break;
                case State.AwaitingConfirm:
                    _buffer = operation;
                    _state = State.AwaitingWithBuffer;
                    break;
                case State.AwaitingWithBuffer:
                    _buffer = TextOperation.Compose(_buffer!, operation);
                    break;
            }
        }

        //The server sent an edit that came after revision Revision. Returns the form of it that fits THIS device's text (the one
        //That was just applied to Text), so a text box can be updated by exactly that change.
        public TextOperation ApplyServer(TextOperation operation)
        {
            // Work out everything first and change nothing until it all fits: a bad edit from the server must not leave this client half-updated.
            TextOperation toApply;
            TextOperation? newOutstanding = _outstanding, newBuffer = _buffer;
            switch (_state)
            {
                case State.Synchronized:
                    toApply = operation;
                    break;
                case State.AwaitingConfirm:
                {
                    var (outstanding1, op1) = TextOperation.Transform(_outstanding!, operation);
                    newOutstanding = outstanding1;
                    toApply = op1;
                    break;
                }
                default:
                {
                    var (outstanding1, op1) = TextOperation.Transform(_outstanding!, operation);
                    var (buffer1, op2) = TextOperation.Transform(_buffer!, op1);
                    newOutstanding = outstanding1;
                    newBuffer = buffer1;
                    toApply = op2;
                    break;
                }
            }

            string next = toApply.Apply(Text);   // throws here, before anything has been changed, if the server's edit does not fit
            Text = next;
            _outstanding = newOutstanding;
            _buffer = newBuffer;
            Revision++;
            return toApply;
        }

        //The server confirmed the edit that was in flight.
        public void ServerAck()
        {
            switch (_state)
            {
                case State.Synchronized:
                    throw new OtException("There is no edit waiting for a confirmation.");
                case State.AwaitingConfirm:
                    Revision++;
                    _outstanding = null;
                    _state = State.Synchronized;
                    break;
                default:
                    Revision++;
                    _outstanding = _buffer;
                    _buffer = null;
                    _state = State.AwaitingConfirm;
                    Send?.Invoke(Revision, _outstanding!);
                    break;
            }
        }

        //Throw away every unconfirmed edit and take the server's text as it is. Used when this device fell too far behind.
        public void ResetTo(string text, int revision)
        {
            Text = text ?? throw new ArgumentNullException(nameof(text));
            Revision = revision;
            _outstanding = null; _buffer = null;
            _state = State.Synchronized;
        }
    }

    //DOGMA II: shared text many devices can type into at once (Same idea as SimpleCRDT)
    //The device that creates a text puts everybody's edits in order, so keep that one online (Others keep typing offline and catch up after)
    //The engine underneath (TextOperation, OtServer, OtClient, OtSession) is internal, you never touch revisions or sequence numbers
    public static class OpTransform
    {
        public sealed class SharedText
        {
            readonly OtDocument _doc;

            internal SharedText(OtDocument Doc)
            {
                _doc = Doc;
                _doc.Changed += c => Changed?.Invoke(c.Text, c.Remote, c.Author);
                _doc.Rejected += Why => Rejected?.Invoke(Why);
            }

            #region Read

            public string Name => _doc.Id;

            //Always the newest text, your own edits included
            public string Text => _doc.Text;

            //False while some of your edits have not been confirmed yet
            public bool IsSynced => !_doc.HasPending;

            //Fires on every change, yours and everyone else's (Text, Remote, Author)
            public event Action<string, bool, string?>? Changed;

            //The owner refused an edit of ours (Why), the text was put back to the owner's version
            public event Action<string>? Rejected;

            #endregion

            #region Update

            public void Insert(int Index, string Content) => _doc.Insert(Index, Content);

            public void Delete(int Index, int Length) => _doc.Delete(Index, Length);

            public void Replace(int Index, int Length, string Content) => _doc.Replace(Index, Length, Content);

            //Overwrite everything, we work out the smallest edit ourselves so other people's typing is kept
            public void SetText(string Content) => _doc.SetText(Content);

            //Wait until everything you typed has been confirmed (Handy before closing the app)
            public Task<bool> WaitUntilSynced(TimeSpan Timeout) => _doc.WaitUntilSyncedAsync(Timeout);

            #endregion
        }

        //The longest text we accept, in characters
        public const int MaxTextChars = OtSession.MaxDocumentChars;

        //One wrapper per text, so events are only hooked up once
        static readonly System.Runtime.CompilerServices.ConditionalWeakTable<OtDocument, SharedText> Wrappers = new();

        internal static SharedText Wrap(OtDocument Doc) => Wrappers.GetValue(Doc, d => new SharedText(d));

        internal static OtSession? Default { get; set; }

        //The node was built again, the old one is gone
        internal static void Reset()
        {
            Default?.Dispose();
            Default = null;
        }

        //Starts shared text on the node made by Identity.CreateNode, call it once
        public static void Start()
        {
            if (Default is not null) return;
            if (Identity.YuukoNode is null) throw new InvalidOperationException("Create the node first (Identity.CreateNode).");
            Default = new OtSession(Identity.YuukoNode);
        }

        #region Create

        //Make a text that THIS device owns, Writers are the devices allowed to edit it (null means anyone connected)
        public static SharedText CreateText(string Name, string Content = "", IEnumerable<string>? Writers = null)
        {
            Start();
            return Wrap(Default!.Create(Name, Content, Writers));
        }

        //Join a text made on another device, comes back with the text up to date
        public static async Task<SharedText> JoinText(string OwnerDevice, string Name)
        {
            Start();
            return Wrap(await Default!.JoinAsync(OwnerDevice, Name).ConfigureAwait(false));
        }

        #endregion

        #region Read

        //Get a text we already made or joined
        public static SharedText? GetText(string Name)
        {
            var doc = Default?.Get(Name);
            return doc is null ? null : Wrap(doc);
        }

        //Names of the texts on this device
        public static IReadOnlyList<string> TextList =>
            Default?.Documents.Select(d => d.Id).ToList() ?? new List<string>();

        #endregion

        #region Delete

        //Stop taking part in a text on this device (If you made it, the others can't reach it anymore)
        public static void RemoveText(string Name) => Default?.Close(Name);

        #endregion
    }
}

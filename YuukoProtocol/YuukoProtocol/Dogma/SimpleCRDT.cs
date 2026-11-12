// SimpleCRDT.cs - DOGMA I: shared documents that merge by themselves (YDotNet / Yjs).
//
//   SimpleCRDT.Start();                                     // once, after Identity.CreateNode: sync documents with every connected device
//   var doc = new SimpleCRDT.SharedDocs("pc", "Shopping list", DateTime.UtcNow, null);
//   doc.CreateLabel("items", "milk\n");                     // a document holds named text fields ("labels")
//   await SimpleCRDT.CreateNewDoc(doc);                     // share it: every connected device gets it
//   doc.AddToLabel("items", "eggs\n");                      // from now on every change is sent by itself
//
// Unlike operational transform there is no owner and no server: any device can edit at any time, even offline, and when devices meet
// their edits merge into the same result on every device. (The merge is Yjs's, through YDotNet.)
//
// How devices stay in step, in plain words:
//   - when you change a document, the change is sent to every connected device ("crdt.update");
//   - when two devices connect (or reconnect), they compare what each has and swap exactly what the other is missing ("crdt.sync"),
//     so a device that was off or out of range catches up by itself;
//   - nobody has to decide whose copy is "newest": merging is the same in any order, so nothing is lost.
// The sync engine is DocSync (DocSync.cs). This file is the document type and the one-line static helpers.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Pariah_Cybersecurity;
using Standart.Hash.xxHash;
using YDotNet.Document;
using YDotNet.Extensions;

namespace YuukoProtocol.Dogma
{
    public static class SimpleCRDT
    {
        //This object is what allows you to see your other devices as items if you so choose; you can choose to represent them as
        // A 3D item (Fingertip)
        // A 2D position (Cursor)
        // A selected text piece (Typewriter cursor) or
        // A graphic (Custom image)

        //You can use multiple at once

        public static class Indicator
        {

        }

        //Limits you can change (Nothing is limited unless you say so)

        //How many documents this device keeps (No limit by default)
        public static int MaxDocs { get => DocSync.MaxDocs; set => DocSync.MaxDocs = value; }

        //How many labels (text fields) one document may have (256 by default)
        public static int MaxLabels { get => DocSync.MaxLabels; set => DocSync.MaxLabels = value; }

        //A change bigger than this is sent in pieces and put back together on the other side (500 KB by default), so a document can be any size
        public static int ChunkBytes { get => DocSync.ChunkBytes; set => DocSync.ChunkBytes = value; }

        //The biggest thing that is put back together (128 MB by default), so another device can't fill your memory by promising a huge one
        public static long MaxChunkedBytes { get => DocSync.MaxChunkedBytes; set => DocSync.MaxChunkedBytes = value; }

        //Making documents

        //A new empty Yjs document with a RANDOM client id. Always make your documents with this, never plain new Doc().
        //Two traps in YDotNet 0.6 that this avoids, both silent: (1) the DEFAULT id comes from a tiny range, and about 6 in 100 pairs of documents made
        //Back to back get the SAME one. Two devices with the same id each believe the other's edits are already in their history, so merging loses or
        //Mixes text and the copies never agree. (2) An explicit id above 32 bits is accepted, and so are the updates made with it, but the other side
        //Reports "Ok" and drops the edit. So the id here is a random 32-bit number.
        public static Doc NewDoc()
        {
            Span<byte> bytes = stackalloc byte[4];
            RandomNumberGenerator.Fill(bytes);
            uint id = BitConverter.ToUInt32(bytes);
            return new Doc(new YDotNet.Document.Options.DocOptions { Id = id == 0 ? 1u : id });
        }

        //The document

        //Convert to Yuuko Definition later
        public class SharedDocs
        {
            public string DeviceName;                  // the device that created it (its id): the only one allowed to remove it, by default
            public DateTime LastUpdated;               // for display only: it is never used to decide whose copy wins
            public Doc Data;
            public string UUID;
            public string LabelName;                   // a human name for the document

            public HashSet<string> TextLabels;
            public ulong ContentHash;                  // a quick fingerprint of the text, to see whether two copies match

            internal readonly object Lock = new();     // Yjs documents are not safe to use from two threads at once
            private Action<byte[]>? _onLocalUpdate;
            private IDisposable? _subscription;
            [ThreadStatic] private static bool _applyingRemote;

            public SharedDocs() { Data = NewDoc(); TextLabels = new HashSet<string>(); UUID = ""; DeviceName = ""; LabelName = ""; }

            public SharedDocs(string deviceName, string labelName, DateTime lastUpdated, Doc? data)
            {
                DeviceName = deviceName;
                LastUpdated = lastUpdated;
                Data = data ?? NewDoc();
                UUID = PasswordGenerator.GeneratePassword(24, true, true, true, true);
                LabelName = labelName;
                TextLabels = new HashSet<string>();
            }

            void UpdateHashAndDate()
            {
                //The hash library can't take no bytes, and a document with only empty text is a real thing (A label that was just made, or emptied)
                var Bytes = System.Text.Encoding.UTF8.GetBytes(TextLabels.Count == 0 ? "" : ReadDoc());
                ContentHash = Bytes.Length == 0 ? 0 : xxHash64.ComputeHash(Bytes);
                LastUpdated = DateTime.UtcNow;
            }

            public void CreateLabel(string Label, string? Content)
            {
                lock (Lock)
                {
                    if (TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Already Exists.");

                    var textType = Data.Text(Label);
                    TextLabels.Add(Label);

                    if (Content != null)
                    {
                        using (var WriteData = Data.WriteTransaction())
                        {
                            textType.Insert(WriteData, 0, Content);
                            WriteData.Commit();
                        }
                    }
                    UpdateHashAndDate();
                }
            }

            public void CreateText(string Label, string Content)
            {
                lock (Lock)
                {
                    if (!TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Doesn't Exist.");

                    var content = Data.Text(Label);
                    using (var WriteData = Data.WriteTransaction())
                    {
                        var currentLength = content.Length(WriteData);
                        content.Insert(WriteData, currentLength, Content);
                        WriteData.Commit();
                    }
                    UpdateHashAndDate();
                }
            }

            public string ReadDoc()
            {
                lock (Lock)
                {
                    if (TextLabels.Count == 0)
                        throw new InvalidOperationException("No Labels Exist.");

                    var sb = new System.Text.StringBuilder();
                    foreach (var item in TextLabels.OrderBy(x => x, StringComparer.Ordinal))   // the same order on every device
                    {
                        var SpecificText = Data.Text(item);
                        using (var ReadData = Data.ReadTransaction())
                            sb.Append(SpecificText.String(ReadData));
                    }
                    return sb.ToString();
                }
            }

            public string ReadLabel(string Label)
            {
                lock (Lock)
                {
                    if (!TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Doesn't Exist.");

                    var SpecificText = Data.Text(Label);
                    using (var ReadData = Data.ReadTransaction())
                        return SpecificText.String(ReadData);
                }
            }

            public void AddToLabel(string Label, string Content, bool Overwrite = false)
            {
                lock (Lock)
                {
                    if (!TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Doesn't Exist.");

                    var text = Data.Text(Label);
                    using (var WriteData = Data.WriteTransaction())
                    {
                        var currentLength = text.Length(WriteData);
                        if (Overwrite)
                        {
                            if (currentLength > 0) text.RemoveRange(WriteData, 0, currentLength);
                            text.Insert(WriteData, 0, Content);
                        }
                        else text.Insert(WriteData, currentLength, Content);
                        WriteData.Commit();
                    }
                    UpdateHashAndDate();
                }
            }

            public void DeleteFromLabel(string Label, int StartingPoint, int? EndPoint)
            {
                lock (Lock)
                {
                    if (!TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Doesn't Exist.");

                    var text = Data.Text(Label);
                    using (var WriteData = Data.WriteTransaction())
                    {
                        var length = text.Length(WriteData);
                        var end = EndPoint ?? (int)length;

                        if (StartingPoint < 0 || StartingPoint > length) throw new ArgumentOutOfRangeException(nameof(StartingPoint));
                        if (end < StartingPoint || end > length) throw new ArgumentOutOfRangeException(nameof(EndPoint));

                        int deleteLength = end - StartingPoint;
                        if (deleteLength > 0) text.RemoveRange(WriteData, (uint)StartingPoint, (uint)deleteLength);
                        WriteData.Commit();
                    }
                    UpdateHashAndDate();
                }
            }

            public void NukeLabel(string Label, bool DeleteLabel = false)
            {
                lock (Lock)
                {
                    if (!TextLabels.Contains(Label))
                        throw new InvalidOperationException("This Label Doesn't Exist.");

                    var text = Data.Text(Label);
                    using (var WriteData = Data.WriteTransaction())
                    {
                        var currentLength = text.Length(WriteData);
                        if (currentLength > 0) text.RemoveRange(WriteData, 0, currentLength);
                        WriteData.Commit();
                    }
                    if (DeleteLabel) TextLabels.Remove(Label);
                    UpdateHashAndDate();
                }
            }

            //Merge changes that came from another device. Safe to call with the same update twice.
            public void ApplyUpdate(byte[] update)
            {
                lock (Lock)
                {
                    _applyingRemote = true;   // so our own change-watcher does not send it straight back out
                    try
                    {
                        using (var WriteData = Data.WriteTransaction())
                        {
                            var result = WriteData.ApplyV1(update);
                            WriteData.Commit();
                            if (result != YDotNet.Document.Transactions.TransactionUpdateResult.Ok)
                                throw new FormatException("That is not a valid document update (" + result + ").");
                        }
                    }
                    finally { _applyingRemote = false; }
                    UpdateHashAndDate();
                }
            }

            //What the other side needs to catch up with this copy, given its state vector (null = everything).
            public byte[] StateDiff(byte[]? theirStateVector)
            {
                lock (Lock)
                    using (var read = Data.ReadTransaction())
                        return read.StateDiffV1(theirStateVector);
            }

            //A short summary of what this copy contains, used to ask another device for what is missing.
            public byte[] StateVector()
            {
                lock (Lock)
                    using (var read = Data.ReadTransaction())
                        return read.StateVectorV1();
            }

            internal void AddLabelFromRemote(string label)
            {
                lock (Lock)
                {
                    if (TextLabels.Add(label)) Data.Text(label);   // asking for a text type creates it
                }
            }

            //Call onLocalUpdate with the bytes of every change made on THIS device (not changes merged in from others).
            internal void Watch(Action<byte[]> onLocalUpdate)
            {
                lock (Lock)
                {
                    _subscription?.Dispose();
                    _onLocalUpdate = onLocalUpdate;
                    _subscription = Data.ObserveUpdatesV1(e =>
                    {
                        if (_applyingRemote) return;
                        _onLocalUpdate?.Invoke(e.Update);
                    });
                }
            }

            internal void StopWatching()
            {
                lock (Lock) { _subscription?.Dispose(); _subscription = null; _onLocalUpdate = null; }
            }
        }

        //The one-line helpers (for a single node per app)

        //The sync engine for this app's node (set by Start).
        public static DocSync? Default { get; private set; }

        //The node was built again, the old one is gone
        internal static void Reset()
        {
            Default?.Dispose();
            Default = null;
        }

        //Documents this app has, by UUID.
        public static IReadOnlyDictionary<string, SharedDocs> ItemList =>
            Default?.Docs ?? new Dictionary<string, SharedDocs>();

        //Starts document sync on the node made by Identity.CreateNode. Call it once.
        public static DocSync Start()
        {
            if (Default is not null) return Default;
            if (Identity.YuukoNode is null) throw new InvalidOperationException("Create the node first (Identity.CreateNode).");
            return Default = new DocSync(Identity.YuukoNode);
        }

        //Share a document with every connected device and keep it in step from now on.
        public static Task CreateNewDoc(SharedDocs doc) => Start().ShareAsync(doc);

        //Remove a document here and on the other devices (only the device that created it may, unless you set DocSync.AnyMemberMayRemove).
        public static Task RemoveDoc(string uuid) => Start().RemoveAsync(uuid);

        //Compare notes with every connected device and swap whatever either is missing.
        public static Task SyncAll() => Start().SyncAllAsync();
    }
}

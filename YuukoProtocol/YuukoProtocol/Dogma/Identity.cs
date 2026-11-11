using Pariah_Cybersecurity;
using System;
using System.Collections.Generic;
using System.ComponentModel.Design;
using System.Dynamic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using WISecureData;
using YuukoProtocol;
using Zenoh;
using static YuukoProtocol.Identity;

namespace YuukoProtocol.Dogma
{
    public static class Identity
    {

        public static EclipseBroker YuukoNode;

        //For compeltely new Yuuko Protocol users, DON'T use this if you have a device already connected to Yuuko Protocol
        //Else you gotta resync them all, or maybe that should be a function
        public static string CreateGroupKey()
        {
            var GroupKey = PasswordGenerator.GeneratePassword(16, true, true, true, true);
            return GroupKey;
        }


        #region Node Setup and Connection

        public class GroupChangeRequestEventArgs : EventArgs
        {
            public string IntroducedBy { get; }
            public string DeviceId { get; }
            public bool IsIntroduction { get; } // true = trust, false = stop trusting

            // This allows the UI to pass the user's decision back down to the network layer
            private readonly TaskCompletionSource<bool> _tcs = new();
            public Task<bool> UserDecisionTask => _tcs.Task;

            public GroupChangeRequestEventArgs(string introducedBy, string deviceId, bool isIntroduction)
            {
                IntroducedBy = introducedBy;
                DeviceId = deviceId;
                IsIntroduction = isIntroduction;
            }

            public void SetResult(bool allowed) => _tcs.TrySetResult(allowed);
        }

        // The UI will hook into this event
        public static event EventHandler<GroupChangeRequestEventArgs>? GroupChangeRequested;


        //Fires when the node was built again (After pairing), call OpTransform.Start(), SimpleCRDT.Start(), HolyMother.Start(), Cogitarium.Start() and DAG.Start(key) again and register your own commands again
        public static event EventHandler? NodeRestarted;

        static EclipseBroker Node => YuukoNode ?? throw new InvalidOperationException("Create the node first (Identity.CreateNode).");

        //What we need to remember so the node can be built again (Pairing builds a second one, and a restart builds the first again)
        static string MyDeviceID, MyDeviceName;
        static bool MyListensToOthers;
        static byte[] MyGroupKey;
        static DeviceDirectory MyDirectory;
        static YuukoIdentity MyIdentity;
        static ZenohBroker MyTransport;
        static readonly List<string> KnownEndpoints = new();

        //Let's assume name is formatted as (DeviceType)(DeviceName)
        public static async Task CreateNode(
            SecureData Password,
            string DeviceID,
            string DeviceName,
            bool ListensToOthers,
            byte[] GroupKey,
            string? TrustedDevices,
            SecureData TrustedDeviceKey)
        {
            MyDeviceID = DeviceID;
            MyDeviceName = DeviceName;
            MyListensToOthers = ListensToOthers;
            MyGroupKey = GroupKey;

            //Let's assume we encrypted and protected our savelist with JSONDataHandler
            MyDirectory = new DeviceDirectory(TrustedDeviceKey, TrustedDevices);
            MyIdentity = YuukoIdentity.LoadOrCreate(DeviceID, DeviceName);

            await StartMainNode();
        }

        //Builds the options we use for every node (Main one and the temporary one for pairing)
        static EclipseBrokerOptions BuildBrokerOptions()
        {
            var BrokerOptions = new EclipseBrokerOptions();

            BrokerOptions.Directory = MyDirectory;

            //We make a group key required for more security
            BrokerOptions.Handshake.PreSharedKey = MyGroupKey;
            BrokerOptions.Handshake.RequirePreSharedKey = true;

            BrokerOptions.GroupChangePolicy = async change =>
            {
                //Create the event args payload
                var args = new GroupChangeRequestEventArgs(
                    change.IntroducedBy,
                    change.DeviceId,
                    change.Kind == GroupChangeKind.Introduce
                );

                //Nobody is listening, so nobody can say yes
                if (GroupChangeRequested is null) return false;

                //Fire the event to your UI layer
                GroupChangeRequested.Invoke(null, args);

                //Await whatever the user clicks on screen (No answer after a minute counts as no)
                var Done = await Task.WhenAny(args.UserDecisionTask, Task.Delay(TimeSpan.FromMinutes(1)));
                return Done == args.UserDecisionTask && args.UserDecisionTask.Result;
            };

            return BrokerOptions;
        }

        static async Task StartMainNode()
        {
            //Get rid of the old one first, it holds the port
            StopMainNode();

            //Anything that was hooked to the old node has to be started again
            OpTransform.Reset();
            SimpleCRDT.Reset();
            HolyMother.Reset();
            DAG.Reset();
            Cogitarium.Reset();

            //Nothing listed means Zenoh picks a free port by itself
            var BrokerSetup = new ZenohBrokerOptions();
            BrokerSetup.DeviceName = MyDeviceName;

            //Devices we paired with, so we can find them again
            foreach (var Endpoint in KnownEndpoints)
            {
                BrokerSetup.ConnectEndpoints.Add(Endpoint);
            }

            var transport = ZenohBroker.Open(BrokerSetup);

            try
            {
                var node = EclipseBroker.Create(transport, MyIdentity, BuildBrokerOptions());
                await node.StartAsync();

                MyTransport = transport;
                YuukoNode = node;
                NodeRestarted?.Invoke(null, EventArgs.Empty);
            }
            catch
            {
                transport.Dispose();
                throw;
            }
        }

        static void StopMainNode()
        {
            YuukoNode?.Dispose();
            MyTransport?.Dispose();
            YuukoNode = null;
            MyTransport = null;
        }

        //Call this when your app closes
        public static void Shutdown()
        {
            StopMainNode();
        }


        public static async Task<string> CreatePairing()
        {
            var offer = Node.BeginPairing();
            return offer.Code;
        }

        public static async Task CancelConnecting()
        {
            Node.CancelPairing();
        }

        //Remember Device name contains the identity of the device
        public static async Task ConnectToDevice(string Key, string DeviceName, string DeviceNickname)
        {
            var code = PairingCode.Parse(Key);

            //The code decides how we reach the other device (Its address and its temporary certificate), so pairing happens on its own node
            PairResult result;

            using (var Reciever = ZenohBroker.Open(code.ToTransportOptions(DeviceName)))
            using (var Joiner = EclipseBroker.Create(Reciever, MyIdentity, BuildBrokerOptions()))
            {
                await Joiner.StartAsync();
                result = await Joiner.PairWithAsync(code, moniker: DeviceNickname);
            }

            if (!result.Success)
            {
                throw new Exception("Pairing failed: " + result.Failure);
            }

            //Remember where they are, then bring our main node back up (It also picks up the new certificate if we joined their group)
            if (code.Endpoint is not null && !KnownEndpoints.Contains(code.Endpoint))
            {
                KnownEndpoints.Add(code.Endpoint);
            }

            await StartMainNode();
        }

        #endregion

        //Device Connections and advanced operations

        //Get all users
        public static List<string> ViewAllConnectedMachines()
        {
            return Node.ConnectedPeers.ToList();  
        }

        public static async Task<bool> IsConnected(string DeviceName)
        {
            return Node.IsConnected(DeviceName);

        }

        public static async Task<bool> HasRecentActivity(string DeviceName)
        {
            return Node.IsOnline(DeviceName);

        }


        //Notify someone connected

        //Notify someone disconnected

        //Audit File

        //If a new group password is given and allowance is given, share with all trusted devices on network to move to new encryptiuon key and auto reconnect


        public class EventChange : EventArgs
        {
            public string DeviceName;
            public StatusChange Status;

            public EventChange (string deviceName, StatusChange status)
            {
                DeviceName = deviceName;
                Status = status;
            }
        }
        public static event EventHandler<EventChange>? ConnectionStatusChange;

        #region GroupHandler

        // Adds a device to the trusted group

        public static async Task TrustDevice(string DeviceName)
        {
            await Node.IntroduceAsync(DeviceName);
        }

        public static async Task UntrustDevice(string DeviceName)
        {
            await Node.RevokeAsync(DeviceName);
        }




        //How to listen for subscribe events

        // In your Main UI Code:
        //YuukoProtocol.Dogma.Identity.GroupChangeRequested += async(sender, e) =>
        //{
        //    string Action = e.IsIntroduction ? "trust" : "stop trusting";
        //    string Message = $"{e.IntroducedBy} wants you to {Action} {e.DeviceId}. Allow?";

            // Show your native popup box (MessageBox, ContentDialog, DisplayAlert, etc.)
        //    bool userClickedYes = await YourCustomPopup.ShowAsync(Message);

            // Pass the boolean choice back to Pariah/Zenoh!
        //    e.SetResult(userClickedYes);
        //};


        #endregion


    #region Controls

    public static async Task KickDevice(string DeviceName, bool Ban, string Reason)
        {
            await Node.KickAsync(DeviceName, Ban, Reason);

            var status = Ban
                ? StatusChange.Banned
                : StatusChange.Disconnected;

            ConnectionStatusChange?.Invoke(
                null,
                new EventChange(DeviceName, status)
            );
        }

        #endregion

        public static void UnbanDevice(string DeviceNickname)
        {
            Node.Unban(DeviceNickname);
        }

        public static async Task<TimeSpan> GetLatency(string DeviceNickname)
        {
            var ping = await Node.PingAsync(DeviceNickname);
            var latency = ping.Elapsed;
            return latency;
        }







    }
}

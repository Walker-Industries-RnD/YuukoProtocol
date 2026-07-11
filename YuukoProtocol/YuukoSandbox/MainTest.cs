using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using YuukoProtocol;

namespace YuukoSandbox
{

    //Fun WIP test site!
    public class MainTest
    {
        public static async Task Main()
        {
            Console.WriteLine("...");
            await Task.Delay(200);
            Console.WriteLine("...");
            await Task.Delay(200);
            Console.WriteLine("...");
            await Task.Delay(200);
            Console.WriteLine("Select Any Key To Continue...");


            Console.ReadKey();
            Console.WriteLine("Reading Credentials...");
            await Task.Delay(500);
            Console.WriteLine("Credentials Scanning...");
            await Task.Delay(800);
            Console.WriteLine("Credentials Accepted.");
            await Task.Delay(500);

            Console.Clear();

            string Banner =
                @"...................................................................................................................
...................................................................................................................
......................................:::::::::::::::::::::::::::::::::::::::......................................
.......................:=+*#%%@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%%#*+=-.......................
..............:=*#@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@%*=::.............
........:=#%@@@@@@@@@@@@@@@%%%%%%%%%%##################%######################%%%%%%%%%%@@@@@@@@@@@@@@@%#+:........
.....:#@@@@@@@@@@%%%#######################%%%%%%%%#%%%%%%%%%%%###%%%%%%%%#####################%%%@@@@@@@@@@%-.....
...:#@@@@@%%%##############################%%@@%%###%%@@%%%@@%%%##%%@@%%%#############################%%%@@@@@%:...
....%@@@%%#################################%%@@%%%##%%@@%%%@@@#%##%%@@%%#################################%%%@@@:...
....%@@@%##################################%%@@%%##%%%@@%%%@@@@%%#%%@@%%################################%##%@@@:...
....%@@@%###################%%#############%%@@%%###%%@@%%%@@@@%%%%%@@%%#######%%#%%##%####################%@@@:...
....%@@@%##########################%%%#####%%@@%%@%#**@@#+*@@@@@%@@%@@%%############%######################%@@@:...
....%@@@%###############%%#######%##%%###%%%%@@#+++++*@@#+*@@#@@%++*@@%%%%#######%##%%#####################%@@@:...
...:%@@@%############%%#%##@@%########%%%*++*@@#+++++*@@#+*@@*#@@#+*@@#++*%%%########@@@###################%@@@:...
...:%@@@%#####%%#######*#@@@%#%####%%%#+++++*@@#+++++*@@#+*@@*+%@@**@@#+++++*%%%######%@@@#*###############%@@@:...
...:%@@@%#####%%#%##%%##@@@##%###%%%*+++++++*@@#+++++*@@#+*@@*+*@@%*@@*..:=+++*%%%#%%###@@@##%%#%%%########%@@@:...
...:%@@@%##########@@##@@%#####%%%*+++++++++*@@#+++++*@@#+*@@*++%@@#@@#:....+++++%%%#####%@@##@@###########%@@@:...
....%@@@%######%##@@##@%###%##%%*+++++++++++*@@#+++++*@@#+*@@*++*@@@@@#+::...-++++*%%##%%##%%#%@@#####%#%##%@@@:...
....%@@@%######*#%@@#*##%@%#%%%+++++++++++++*@@%*++++#@@*+*@@*+++*@@@@#+++=....:++++%%##%@@####@@######%%##%@@@:...
....%@@@%########%@%##@@@##%%#+++++++++++++++%@@@***%@@@++*@@*++++%@@@#+=++++-...:+++*%%##@@@##@@%#########%@@@:...
....%@@@%###%#@##%@*%@@%##%%#+++++++++++++++++@@@@@@@@@*++*@@*++++*@@@#+=-=++++=:..+++*%%###@@@*@%#%@######%@@@:...
...:%@@@%##%#%@##%#@@##*##%#+++++++++++++++++++%@@@@@%*+++*@@*+++++#@@#++++++++++++++++#%#####@@###%@%#####%@@@:...
...:%@@@%####@@%#%@%##%##%%+++++++++++++++++++++++++++++++++++++++++=+++++++=-++++++++++#%##@###%##%@@#####%@@@:...
...:%@@@%#%##@@%####%@%#%%++++++++++++++++++++++++--=++++++++++-=++=++=+++++=:-++++++++++%%#%@@##*#@@@#####%@@@:...
...:%@@@%####@@@##%@@%#%%*++++++++++++++++++++-.......:+++++=-:-=+-....--.-+++:==++++++++*%%#%@@%##@@@*####%@@@:...
....%@@@%##*#@@%#%@@%##%%+++++++++++++++++++=:=+-.......-=:=................-:==-+++++++++%%###@@%*@@%#####%@@@:...
....%@@@%%####@%#@@##*#%#++++++++++++++-=++::===..........-++=................=-=+++++++++#%####@@#%@##%#%#%@@@:...
....%@@@%##%##%#%@#####%#+++==+++++++=...--++==-.....:..-+++++=-..............++++++++++++*%#####%@%%##@###%@@@:...
....%@@@%##@###@@##%@##%*++.....=+++=.....:+=+++=:...::::=++++=:.............-++++++++++++*%##@%##%@##%@###%@@@:...
...:%@@@%##@@##%##%@%##%*+-................+=+++++=--=:.-+++++++-.............=+++++++++++*%##%@@####%@@###%@@@:...
...:%@@@%##@@@#*##@@###%*+---.............:+++++++++++++++++++++=:.............-++++++++++*%###@@%###@@%###%@@@:...
...:%@@@%##%@@%##@@@###%#+++++-............+++++++++++++++++++..:............-++++++++++++*%%##%@@##%@@%#%#%@@@:...
...:%@@@%%##@@@##@@####%#++++++=..........:++++++++++++++++=+=.:............=+++++++++++++#%####@@%#@@%#*##%@@@:...
....%@@@%#*##@@%#@%####%%*++=+++=..........-+++++++++++++++++:.:-...........=+++++++++++++%%####%@#%@%#####%@@@:...
....%@@@%##%##%@*@###%##%*+++=++++:........=++++++++++++++=:==::....:=:.....+++++++++++++*%%#@###@*@###%#%#%@@@:...
....%@@@%##@%###@@##%@##%%+++++++++=.......:+++++++++++++++-.........:-....==.=++++++++++%%##@%##%@###@%###%@@@:...
....%@@@%##%@@###%##@@###%%+++++++++++=.....:++++++++++++=...-==-===+-...:....+++:=+++++%%###@@#####%@@####%@@@:...
....%@@@%#%#%@@%####@@%###%#++++++++++++-....:=++++++++++-:::...--:..........-++=..++++#%#*##@@####@@@#####%@@@:...
...:%@@@%####%@@@%##@@%####%#+++++++++++++++++++++++++:........................=++++++#%####%@@##@@@@##%###%@@@:...
...:%@@@%#%####@@@%#%@@##@##%%+++++++++++++++++++++++=........................=++++++#%#%@##@@##@@@%#*#####%@@@:...
...:%@@@%###%#*##@@@#%@##%@%#%%*+++++++++++++++++++++++=-:...::...............=++++*%%#%@%##@%%@@%#####%%##%@@@:...
...:%@@@%##########%@%@###@@##%%#++++++++++++++++++++++++++++++++=...........-++++#@%##@@##%@@@*###%#######%@@@:...
....%@@@%######%@%####@@##@@@###%%#+++++++++++++++++++++++++++++++-.........=+++*%%###@@@##%%###%@@########%@@@:...
....%@@@%########@@@%###*##@@%#*#%%%#+++++++++++++++++++++++++++++++=:...=++++#@%%###%@@#####%@@@%#########%@@@:...
....%@@@%######%%#%@@@@@###%@@##@%##%%%*+++++++++++++++++++++++++++++++++++*#%%##%@##@@%##%@@@@@###########%@@@:...
....%@@@%#######%%###@@@@@@##@@##@@%#%#%%%*+++++++++++++++++++++++++++++*%%%%##%@@##@@#%@@@@@%#############%@@@:...
...:%@@@%######%###%####@@@@@##%##@@@######%@%*+++++++++++++++++++++*%@%#%%##%@@@##%#%@@@@###*#############%@@@:...
...:#@@@%####################%%%%##%@@@####%%%%%%%%%###########%%%%%%%%%####@@@%#*%%###########%%%%#######%@@@%:...
....*@@@%###############%@%%#*****####%@@%*###%%%#%##%%%%%%%%%######%####@@@##***#%%%##%%%%######%%#######%@@@#:...
....=@@@%%###########%%%#%*+++##%@@@@@@@@@@%#**###%%%%###%##%%%@%%###**#%@@@@@@@@@%##+++*%#####%%########%%@@@+....
.....#@@@%%#######%%#####*+++++++*%##%######%@@@@@####%@%##@%####%@@@@@%########%#++++++++###%%##########%@@@%:....
.....=@@@@##########%###++++++++++++%##*%@@@@@@%###%@%#####%#%@%####@@@@@@@%*#%++++++++++++##############%@@@+.....
......#@@@%###########*+++++++++++++++#%%@@@%####%@%###%###%%%#%@@####%%@@@%#++++++++++++++++###########%@@@%......
.......%@@@%#######%*++++++++++++%%*#%%%%######@@%###%%######%####@@%#%###%%%%#*%%*+++++++++++*%#######%@@@@.......
.......-@@@@%####%*++++++++++++##++*%*+#%#%%##@@#%%%#############%#%@%######+*##++##++++++++++++*%##%#%@@@@=.......
........=@@@@%####%%###++++++*#*++++++#%####%######%%########%########%####%#*+++++*#*++++++###%%####%@@@@+........
.........-@@@@%#####%###%*++##+++++++++++*%%###%################%%#%####%*+++++++++++*#++*%##%######%@@@@+.........
..........-%@@@%##%%######%#*++++++#***++++++*###%###############%####+++++++**++++++++#%##########%@@@@=..........
...........-%@@@%%%%#####%#+++++++#***%*##*+++++++++***********++++++++++***+##*++++++++*%#%######%@@@@-...........
............:#@@@@%%#####*++++++++++**#*#*%*#*#*+++++++++++++++++++*##*####%**#*++++++++++######%@@@@%:............
..............=@@@@%#####%*+++++++++++++****#*#*#+*%**#**####*###*+*#*#**#**++++++++++++*%#####%@@@@+..............
...............:%@@@@%%#%##%*+++++++++++++++++**+++*%**#*#*##*#**#+**+++++++++++++++++*%##%#%%@@@@@:...............
.................=%@@@@%#####%*+++++++++++#*#*****+++++++++++++++***++##**++++++++++*%%####%%@@@@+.................
..................:*@@@@%%%####%%*++++++**#*#++#*%*#*##***#*#*%***##++#**#++++++++%%#####%%@@@@#:..................
....................:#@@@@%%######%%*+++++++*******##**##*%*#*%*#+*#*+++++++++*#%######%%@@@@#-....................
......................:*@@@@%%############*+++++++++++++++++++++++++++++*#############%@@@@#-......................
........................:#@@@@@%%#######%#####%%%%###############%%%%#############%%%@@@@%:........................
..........................:+@@@@@%%######################################%%#####%%@@@@@*:..........................
.............................-%@@@@@%%%########%%######%##########%%##########%%@@@@@=:............................
...............................:#@@@@@%%######%%######%%###################%%@@@@@#-...............................
..................................-#@@@@@%%#############################%%@@@@@%=..................................
.....................................=%@@@@@%%%###################%%%%%@@@@@@+:....................................
........................................=%@@@@@@%#################%%@@@@@%+:.......................................
...........................................-%@@@@@@%%##########%@@@@@@%=...........................................
..............................................-#@@@@@@@%%%%%%@@@@@@#=..............................................
.................................................:=#@@@@@@@@@@@%=:.................................................
......................................................+@@@@@*:.....................................................
.........................................................:.........................................................
...................................................................................................................
...................................................................................................................";


            Console.WriteLine(Banner);
            await Task.Delay(2000);
            Console.Clear();

            Console.WriteLine("Welcome, Kouzaki Yuuko.");
            await Task.Delay(200);
            Console.WriteLine("Running Automated Tests...");

            var testPacketGeneric = YuukoPacket.FromBytes("XM3", Encoding.UTF8.GetBytes("The XM3 is a revolutionary operating system designed for the Tactical Surface Fighters (TSFs). It drastically improves the mechas' combat capabilities and significantly reduces pilot fatality rates by optimizing movement, handling data dynamically, and utilizing advanced flight mechanics."));

            //Generic tests
            //Basic packet test

            Console.WriteLine("Creating Broker...");
            Console.WriteLine("Packet Test");

            var BasicPacketBroker = new LocalBroker();

            await BasicPacketBroker.PublishAsync("UN/AlternativeProject/AlternativeIIII", testPacketGeneric);

            var BasicPacketStored = await BasicPacketBroker.RequestAsync("UN/AlternativeProject/AlternativeIIII");
            Console.WriteLine("Registered Message: " + BasicPacketStored[0].Name + " Data: " + BasicPacketStored[0].DataAsString());
            Console.WriteLine(Environment.NewLine);
            //Listen test

            Console.WriteLine("Listening Test...");

            await BasicPacketBroker.SubscribeAsync("UN/AlternativeProject/AlternativeIIII", async pkt =>
            {
                Console.WriteLine(
                    $"Message recieved! " + Environment.NewLine +
                    $"Topic: {pkt.Name}" + Environment.NewLine +
                    $"Data: {pkt.DataAsString()}");
                await Task.CompletedTask;
            });

            await BasicPacketBroker.PublishAsync("UN/AlternativeProject/AlternativeIIII", testPacketGeneric);

            //Topic dictionary test
            Console.WriteLine("Topic Dictionary Test...");

            var TSFModule = "/YohokamaBase/Hangar/TSF/Inventory";

            var testPacketTSF = YuukoPacket.FromBytes("TSF Message", Encoding.UTF8.GetBytes("English can eat shit???"));


            Console.WriteLine(Environment.NewLine);

            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, testPacketTSF);

            Console.WriteLine("Data I Sent To: " + YuukoTopics.XRUIOSEvents);

            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents + TSFModule, testPacketTSF);

            Console.WriteLine("Data II Sent To: " + YuukoTopics.XRUIOSEvents + TSFModule);


            //Tombstone test

            var f4PhantomPacket = YuukoPacket.FromBytes("F-4 Phantom", Encoding.UTF8.GetBytes("First generation pioneer."));
            var gekishinPacket = YuukoPacket.FromBytes("Type-82 Gekishin", Encoding.UTF8.GetBytes("Japan's early armored wall."));
            var f15EaglePacket = YuukoPacket.FromBytes("F-15 Eagle", Encoding.UTF8.GetBytes("The standard-bearer of the second generation."));
            var shiranuiPacket = YuukoPacket.FromBytes("Type-94 Shiranui", Encoding.UTF8.GetBytes("The pride of the Imperial Japanese Army."));
            var f22RaptorPacket = YuukoPacket.FromBytes("F-22A Raptor", Encoding.UTF8.GetBytes("Stealth and absolute superiority."));
            var terminatorPacket = YuukoPacket.FromBytes("Su-37UB Terminator", Encoding.UTF8.GetBytes("Vicious close-quarters Soviet brutality."));
            var takemikazuchiPacket = YuukoPacket.FromBytes("Type-00 Takemikazuchi", Encoding.UTF8.GetBytes("Built for royalty, painted in purple blood."));
            var shiranuiSecondPacket = YuukoPacket.FromBytes("Type-04 Shiranui Second", Encoding.UTF8.GetBytes("Pushing the limits of the Prominence Project."));
            var f18HornetPacket = YuukoPacket.FromBytes("F-18E/F Super Hornet", Encoding.UTF8.GetBytes("Versatile carrier-based fleet defender."));
            var mig21BalalaikaPacket = YuukoPacket.FromBytes("MiG-21 Balalaika", Encoding.UTF8.GetBytes("The stubborn workhorse of the Eastern Front."));

            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, f4PhantomPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, gekishinPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, f15EaglePacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, shiranuiPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, f22RaptorPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, terminatorPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, takemikazuchiPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, shiranuiSecondPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, f18HornetPacket);
            await BasicPacketBroker.PublishAsync(YuukoTopics.XRUIOSEvents, mig21BalalaikaPacket);


            Console.WriteLine("Data I Sent." + Environment.NewLine);
            Console.WriteLine("Data: ");

            var TombstoneRecords = await BasicPacketBroker.RequestAsync(YuukoTopics.XRUIOSEvents);

            var TombStoneRecordLabel = 0;
            foreach (var item in TombstoneRecords)
            {
                Console.WriteLine("Tombstone: " + TombStoneRecordLabel);
                Console.WriteLine(item.Name);
                Console.WriteLine(item.DataAsString());
                Console.WriteLine(Environment.NewLine);
                TombStoneRecordLabel++;

            }


            //Fire and forget test

            await BasicPacketBroker.PublishEphemeralAsync("YokohamaBase/00Unit/SecretKeyMsg", "Message",
                Encoding.UTF8.GetBytes("ShittimChest"));

            await BasicPacketBroker.SubscribeAsync("YokohamaBase/00Unit/SecretKeyMsg", async pkt =>
            {
                Console.WriteLine(
                    $"Message recieved! " + Environment.NewLine +
                    $"Topic: {pkt.Name}" + Environment.NewLine +
                    $"Data: {pkt.DataAsString()}");
                await Task.CompletedTask;
            });

            Console.WriteLine("Data Deleted. Checking...");

            Console.WriteLine((await BasicPacketBroker.RequestAsync("YokohamaBase/00Unit/SecretKeyMsg")).Count);

            Console.WriteLine(Environment.NewLine);

            //Multi listener to one packet test

            Console.WriteLine("Testing Multi Listener System");

            void BETAALERT(string alertLocation)
            {
                Console.WriteLine("ALERT, ALERT, BETA SPOTTED FROM " + alertLocation + " BASE!");
                Console.WriteLine("ALERT, ALERT, BETA SPOTTED FROM " + alertLocation + " BASE!");
                Console.WriteLine("ALERT, ALERT, BETA SPOTTED FROM " + alertLocation + " BASE!");
                Console.WriteLine("ATTENTION. A BETA breakthrough has been confirmed and the frontlines have completely collapsed. " +
                    "The perimeter is breached, with enemy vector units estimated to reach the base within four minutes. Laser-class" +
                    " activity has been detected, closing all airspace and threatening instant incineration for any air units or " +
                    "surface ejections. All TSF pilots must engage close-combat blades, conserve ammunition, and protect Alternative" +
                    " IV at all costs. Ground personnel are ordered to issue assault rifles, establish final defensive perimeters," +
                    " and prepare for a total lockdown as no extraction will be provided.");

                Console.WriteLine(Environment.NewLine);
            }

            await BasicPacketBroker.SubscribeAsync("BETA-ALERT", async packet =>
            {
                BETAALERT("YOKOHAMA BASE");
                await Task.CompletedTask; // Satisfies the async requirement
            });

            await BasicPacketBroker.SubscribeAsync("BETA-ALERT", async packet =>
            {
                BETAALERT("YUKON BASE");
                await Task.CompletedTask; // Satisfies the async requirement
            });
            await BasicPacketBroker.SubscribeAsync("BETA-ALERT", async packet =>
            {
                BETAALERT("ARASHIYAMA BASE");
                await Task.CompletedTask; // Satisfies the async requirement
            });
            await BasicPacketBroker.SubscribeAsync("BETA-ALERT", async packet =>
            {
                BETAALERT("ATSUGI BASE");
                await Task.CompletedTask; // Satisfies the async requirement
            });
            await BasicPacketBroker.SubscribeAsync("BETA-ALERT", async packet =>
            {
                BETAALERT("PETROPAVLOVSK-KAMCHATSKY BASE");
                await Task.CompletedTask; // Satisfies the async requirement
            });


            var BaseWarningKey = YuukoPacket.FromBytes("WARNING", Encoding.UTF8.GetBytes("TRUE"));
            await BasicPacketBroker.PublishAsync("BETA-ALERT", BaseWarningKey);




            var baseDummyData = YuukoPacket.FromBytes("Key", Encoding.UTF8.GetBytes(("This is a UN sanctioned test. Unauthorized use of this may lead to legislation at the federal or international leve.")));

            //Process to Process

            var YokohamaCaseA = new LocalBroker();
            await BasicPacketBroker.PublishAsync("YokohamaBase/CentralControl/SectionA/CaseA", baseDummyData);


            //Security Encforcement

            //Fallback Protocols

            //SCCN TESTING
            //StreetPass

            //Satellite Election

            //Signed Relay Hops

            //Tamper Voting

            //Local vs Room vs Internet

            //Sending splat to server

            //Server building

            //Server sending to users as livestream










            //Secure connection test

            //Do we trust this request?

            //Streetpass Test

            //Live theme switch

            //Status dashboard

            //Folder sync

            //Tracking streams

            //Gateway peer registries

            //Diagnostic run up

            //"Catch me up" data snapshot

            //Separate app request

            //
        }
    }

}

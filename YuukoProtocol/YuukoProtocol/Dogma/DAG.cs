// DAG.cs - DOGMA IV: keeps shared folders the same on every device that shares them. This file is the encrypted repository (CRUD), DAG.Sync.cs is the sync itself.
//
//   await DAG.Start(key);                                     // load the repository and start listening for other devices
//
//   // Create: share a folder from this device, or join one another device shared (Same UUID, your own path)
//   var entry = await DAG.ShareFolder(directoryPath, new List<string> { "pc", "laptop" });
//   await DAG.JoinFolder(entry.UUID, directoryPath, new List<string> { "pc", "laptop" });
//
//   // Read: ask another device
//   bool has = await DAG.CheckIfFolderExists("pc", uuid);
//   bool newer = await DAG.CheckForUpdate("pc", uuid);
//   var entries = await DAG.GetAllEntries(null, key);
//   var entry = await DAG.GetSpecificEntry(uuid, key);
//   var entry = await DAG.GetSpecificEntryByDirectoryPath(directoryPath, key);
//
//   // Update: pull what another device has, or tell everyone to pull from you
//   var result = await DAG.SyncFolder("pc", uuid);            // result.Downloaded, result.Deleted, result.Conflicts, result.Errors
//   await DAG.BroadcastUpdate(uuid);
//   await DAG.UpdateVariable(uuid, updatedEntry, key);
//   await DAG.UpdateVariableByDirectoryPath(directoryPath, updatedEntry, key);
//
//   // Delete: stop sharing (The files stay where they are)
//   await DAG.StopSharing(uuid);
//   await DAG.DeleteVariable(uuid, key);
//   await DAG.DeleteVariableByDirectoryPath(directoryPath, key);
//
// How it works: each device keeps an encrypted repository of the folders it shares: the root hash, last update time, status, the devices
// allowed to sync it, its own path for the folder, a unique UUID and the state the folder was in when the devices last agreed (The baseline).
// A folder is a list of files, each file is cut in 256 KB chunks and its hash is the hash of its chunk hashes, so two devices with the same
// content have the same hash no matter where the file is. SyncFolder asks the other device for its list, compares it to ours and to the
// baseline, and downloads only what changed, chunk by chunk, checking the hash before the file is put in place.
//
// Rules: a file only one side changed follows that side. A deleted file is moved to .yuuko/trash, never erased. If both sides changed the
// same file the newest wins on both devices and the other one is kept next to it as "name (conflict 1a2b3c4d).ext", so nothing is lost and
// both devices end up with the same files. A download that stops half way continues where it stopped the next time (.yuuko/partial).
// Devices only get files from folders they are listed for, and only files that are in the folder's own list, never a path they make up.
//
// What it does NOT do: it syncs files only (empty folders aren't kept), it doesn't follow shortcuts or symlinks, a folder is at most 4000
// files and a file at most 4 GB, the baseline is one per folder (not one per device), and it doesn't merge the inside of a file.

using Pariah_Cybersecurity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using WISecureData;
using YDotNet.Document;
using static Pariah_Cybersecurity.DataHandler;
using static Pariah_Cybersecurity.EasyPQC;

namespace YuukoProtocol.Dogma
{
    public static partial class DAG
    {


        public record Tome
        {
            public string DirectoryID;
            public SecureData AccessUsername;
            public SecureData AccessPassword;

            Bindings.DirectoryManager DataPaths;

            public Tome() { }

            public Tome(string directoryID, SecureData accessUsername, SecureData accessPassword, Bindings.DirectoryManager dataPaths)
            {
                DirectoryID = directoryID;
                AccessUsername = accessUsername;
                AccessPassword = accessPassword;
                DataPaths = dataPaths;
            }

        }

        public static HashSet<Tome> WatchedFolders;

        //Where the encrypted repository is saved (Was the text "CommonProgramFiles", which is a folder name inside wherever the app was started)
        public static string RepoPath { get; set; } = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "YuukoProtocol");

        //StoragePath is the parent of where all Yuuko Tomes are saved


        public static async Task InitializeRepoFile(string storagePath, string? GroupName = "YuukoProtocolDAG")
        {

            //Let's check if a repo file exists here; if it does, we cancel

            if (File.Exists(Path.Combine(storagePath, GroupName)))
            {
                throw new InvalidOperationException("A Repo Has Already Been Initialized Here.");
            }

            {
                await JSONDataHandler.CreateJsonFile(GroupName, storagePath, new JsonObject());

            }

        }


        //What if multiple different sources want to sync the same file? How do we stop spam?
        //We create a public accesible list to say what has been updated, allowing an app to know "This has been updated thanks to something elsewhere"


        public record RepositoryEntry
        {
            public string Hash;
            public DateTime LastUpdated;
            public string Status; //Sitting, Update Pending, Completing
            public List<string> Devices;
            public string ParentPath;

            public string UUID;

            //What every file looked like the last time the devices agreed, so we can tell who changed what (Path is relative to ParentPath)
            public Dictionary<string, FileState> Baseline = new();

            public RepositoryEntry() { }

            public RepositoryEntry (string hash, DateTime lastUpdated, string status, List<string> devices, string parentPath)
            {
                Hash = hash;
                LastUpdated = lastUpdated;
                Status = status;
                Devices = devices;
                UUID = PasswordGenerator.GeneratePassword(24, true, true, true, false);
                ParentPath = parentPath;
            }
        }
        
        

        public static async Task SetupRepo(SecureData key)
        {
            //Should be encrypted VIA user key
            //?

            var savePath = RepoPath;

            await JSONDataHandler.CreateJsonFile("Yuuko Repository", savePath, new JsonObject());

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            await JSONDataHandler.AddToJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", new HashSet<RepositoryEntry>(), key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }


        //CRUD format for editing, add error handling later
        //C
        public static async Task CreateNewEntry(RepositoryEntry Entry, SecureData key)
        {
            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>) await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            repoList.Add(Entry);

            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);
        }

        //R
        public static async Task<HashSet<RepositoryEntry>> GetAllEntries(RepositoryEntry Entry, SecureData key)
        {
            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            return repoList;
        }

        public static async Task<RepositoryEntry> GetSpecificEntry(string UUID, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            RepositoryEntry chosenData = default;

            foreach (var item in repoList)
            {

                if (item.UUID == UUID)
                {
                    chosenData = item;
                }

            }


            return chosenData;

        }

        public static async Task<RepositoryEntry> GetSpecificEntryByDirectoryPath(string DirectoryPath, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            RepositoryEntry chosenData = default;

            foreach (var item in repoList)
            {

                if (item.ParentPath == DirectoryPath)
                {
                    chosenData = item;
                }

            }


            return chosenData;

        }
        //U
        public static async Task UpdateVariable(string UUID, RepositoryEntry Entry, SecureData key)
        {
            Entry.UUID = UUID;

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            //Take the old one out first, or both stay
            repoList.RemoveWhere(item => item.UUID == UUID);
            repoList.Add(Entry);


            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }
        public static async Task UpdateVariableByDirectoryPath(string DirectoryPath, RepositoryEntry Entry, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            var old = repoList.FirstOrDefault(item => item.ParentPath == DirectoryPath);
            if (old != null)
            {
                Entry.UUID = old.UUID;
                repoList.Remove(old);
            }

            repoList.Add(Entry);


            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }

        //D
        public static async Task DeleteVariable(string UUID, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            foreach (var item in repoList)
            {

                if (item.UUID == UUID)
                {
                    repoList.Remove(item);
                    break;
                }

            }


            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }

        public static async Task DeleteVariable(RepositoryEntry Item, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            repoList.RemoveWhere(item => item.UUID == Item.UUID);

            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }

        public static async Task DeleteVariableByDirectoryPath(string DirectoryPath, SecureData key)
        {

            var savePath = RepoPath;

            var loadedJSON = await JSONDataHandler.LoadJsonFile("Yuuko Repository", savePath);

            var repoList = (HashSet<RepositoryEntry>)await JSONDataHandler.GetVariable<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", key);

            foreach (var item in repoList)
            {

                if (item.ParentPath == DirectoryPath)
                {
                    repoList.Remove(item);
                    break;
                }

            }


            await JSONDataHandler.UpdateJson<HashSet<RepositoryEntry>>(loadedJSON, "Data Cache", repoList, key);

            await JSONDataHandler.SaveJson(loadedJSON);

        }




        //Logic to handle updating repos (Including continuing pushes)
        //I don't think we need tomes anymore

        //Check for updates (On this device, on other device), Compare difference, Update (Will auto continue update if it was stopped)
        //Check if folder exists on other device 
        //Maybe a method to auto run the syncer every x minutes? And maybe a way to exclude files over a specific size

        public static async Task<bool> ReturnIfFolderExists(string Device, string DirectoryPath, SecureData key)
        {
            try
            {
                var fileExists = await GetSpecificEntryByDirectoryPath(DirectoryPath, key);
                if (fileExists != null)
                {
                    return true;
                }

                return false;
            }

            catch (Exception ex)
            {
                return false;
            }
        }

    }
}

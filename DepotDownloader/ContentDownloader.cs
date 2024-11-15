// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    class ContentDownloaderException(string value) : Exception(value)
    {
    }

    static class ContentDownloader
    {
        public const uint INVALID_APP_ID = uint.MaxValue;
        public const uint INVALID_DEPOT_ID = uint.MaxValue;
        public const ulong INVALID_MANIFEST_ID = ulong.MaxValue;
        public const string DEFAULT_BRANCH = "public";

        public static DownloadConfig Config = new();
        public static RawClient RawClient = new();

        private static Steam3Session steam3;
        private static CDNClientPool cdnPool;
        private static string depotPath;
        private const string DEFAULT_DOWNLOAD_DIR = "depots";
        private const string CONFIG_DIR = ".DepotDownloader";
        private const string DEPOT_KEY_DIR = "keys";
        private static readonly string STAGING_DIR = Path.Combine(CONFIG_DIR, "staging");

        private sealed class DepotDownloadInfo(
            uint depotid, uint appId, ulong manifestId, string branch,
            string installDir, byte[] depotKey)
        {
            public uint DepotId { get; } = depotid;
            public uint AppId { get; } = appId;
            public ulong ManifestId { get; } = manifestId;
            public string Branch { get; } = branch;
            public string InstallDir { get; } = installDir;
            public byte[] DepotKey { get; } = depotKey;
        }

        static bool CreateDirectories(uint depotId, uint depotVersion, out string installDir)
        {
            installDir = null;
            try
            {
                Directory.CreateDirectory(DEFAULT_DOWNLOAD_DIR);

                depotPath = Path.Combine(DEFAULT_DOWNLOAD_DIR, depotId.ToString());
                Directory.CreateDirectory(depotPath);
                Directory.CreateDirectory(DEPOT_KEY_DIR);
                installDir = depotPath;
            }
            catch
            {
                return false;
            }

            return true;
        }

        static bool TestIsFileIncluded(string filename)
        {
            return true;
        }


        static async Task<bool> AccountHasAccess(uint depotId)
        {
            if (steam3 == null || steam3.steamUser.SteamID == null || (steam3.Licenses == null && steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser))
                return false;

            IEnumerable<uint> licenseQuery;
            if (steam3.steamUser.SteamID.AccountType == EAccountType.AnonUser)
            {
                licenseQuery = [17906];
            }
            else
            {
                licenseQuery = steam3.Licenses.Select(x => x.PackageID).Distinct();
            }

            await steam3.RequestPackageInfo(licenseQuery);

            foreach (var license in licenseQuery)
            {
                if (steam3.PackageInfo.TryGetValue(license, out var package) && package != null)
                {
                    if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;

                    if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;
                }
            }

            return false;
        }

        internal static KeyValue GetSteam3AppSection(uint appId, EAppInfoSection section)
        {
            if (steam3 == null || steam3.AppInfo == null)
            {
                return null;
            }

            if (!steam3.AppInfo.TryGetValue(appId, out var app) || app == null)
            {
                return null;
            }

            var appinfo = app.KeyValues;
            var section_key = section switch
            {
                EAppInfoSection.Common => "common",
                EAppInfoSection.Extended => "extended",
                EAppInfoSection.Config => "config",
                EAppInfoSection.Depots => "depots",
                _ => throw new NotImplementedException(),
            };
            var section_kv = appinfo.Children.Where(c => c.Name == section_key).FirstOrDefault();
            return section_kv;
        }

        static uint GetSteam3AppBuildNumber(uint appId, string branch)
        {
            if (appId == INVALID_APP_ID)
                return 0;


            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var branches = depots["branches"];
            var node = branches[branch];

            if (node == KeyValue.Invalid)
                return 0;

            var buildid = node["buildid"];

            if (buildid == KeyValue.Invalid)
                return 0;

            return uint.Parse(buildid.Value);
        }

        static async Task<ulong> GetSteam3DepotManifest(uint depotId, uint appId, string branch)
        {
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var depotChild = depots[depotId.ToString()];

            if (depotChild == KeyValue.Invalid)
                return INVALID_MANIFEST_ID;

            // Shared depots can either provide manifests, or leave you relying on their parent app.
            // It seems that with the latter, "sharedinstall" will exist (and equals 2 in the one existance I know of).
            // Rather than relay on the unknown sharedinstall key, just look for manifests. Test cases: 111710, 346680.
            if (depotChild["manifests"] == KeyValue.Invalid && depotChild["depotfromapp"] != KeyValue.Invalid)
            {
                var otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
                if (otherAppId == appId)
                {
                    // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                    Console.WriteLine("App {0}, Depot {1} has depotfromapp of {2}!",
                        appId, depotId, otherAppId);
                    return INVALID_MANIFEST_ID;
                }

                await steam3.RequestAppInfo(otherAppId);

                return await GetSteam3DepotManifest(depotId, otherAppId, branch);
            }

            var manifests = depotChild["manifests"];
            var manifests_encrypted = depotChild["encryptedmanifests"];

            if (manifests.Children.Count == 0 && manifests_encrypted.Children.Count == 0)
                return INVALID_MANIFEST_ID;

            var node = manifests[branch]["gid"];

            if (node == KeyValue.Invalid && !string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
            {
                var node_encrypted = manifests_encrypted[branch];
                if (node_encrypted != KeyValue.Invalid)
                {
                    var password = Config.BetaPassword;
                    while (string.IsNullOrEmpty(password))
                    {
                        Console.Write("Please enter the password for branch {0}: ", branch);
                        Config.BetaPassword = password = Console.ReadLine();
                    }

                    var encrypted_gid = node_encrypted["gid"];

                    if (encrypted_gid != KeyValue.Invalid)
                    {
                        // Submit the password to Steam now to get encryption keys
                        await steam3.CheckAppBetaPassword(appId, Config.BetaPassword);

                        if (!steam3.AppBetaPasswords.TryGetValue(branch, out var appBetaPassword))
                        {
                            Console.WriteLine("Password was invalid for branch {0}", branch);
                            return INVALID_MANIFEST_ID;
                        }

                        var input = Util.DecodeHexString(encrypted_gid.Value);
                        byte[] manifest_bytes;
                        try
                        {
                            manifest_bytes = Util.SymmetricDecryptECB(input, appBetaPassword);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Failed to decrypt branch {0}: {1}", branch, e.Message);
                            return INVALID_MANIFEST_ID;
                        }

                        return BitConverter.ToUInt64(manifest_bytes, 0);
                    }

                    Console.WriteLine("Unhandled depot encryption for depotId {0}", depotId);
                    return INVALID_MANIFEST_ID;
                }

                return INVALID_MANIFEST_ID;
            }

            if (node.Value == null)
                return INVALID_MANIFEST_ID;

            return ulong.Parse(node.Value);
        }

        static string GetAppName(uint appId)
        {
            var info = GetSteam3AppSection(appId, EAppInfoSection.Common);
            if (info == null)
                return string.Empty;

            return info["name"].AsString();
        }

        public static bool InitializeSteam3(string username, string password)
        {
            string loginToken = null;

            if (username != null && Config.RememberPassword)
            {
                _ = AccountSettingsStore.Instance.LoginTokens.TryGetValue(username, out loginToken);
            }

            steam3 = new Steam3Session(
                new SteamUser.LogOnDetails
                {
                    Username = username,
                    Password = loginToken == null ? password : null,
                    ShouldRememberPassword = Config.RememberPassword,
                    AccessToken = loginToken,
                    LoginID = Config.LoginID ?? 0x534B32, // "SK2"
                }
            );

            if (!steam3.WaitForCredentials())
            {
                Console.WriteLine("Unable to get steam3 credentials.");
                return false;
            }

            Task.Run(steam3.TickCallbacks);

            return true;
        }

        public static void ShutdownSteam3()
        {
            if (cdnPool != null)
            {
                cdnPool.Shutdown();
                cdnPool = null;
            }

            if (steam3 == null)
                return;

            steam3.Disconnect();
        }

        public static async Task DownloadPubfileAsync(uint appId, ulong publishedFileId)
        {
            var details = await steam3.GetPublishedFileDetails(appId, publishedFileId);

            if (details?.hcontent_file > 0)
            {
                await DownloadAppAsync(appId, new List<(uint, ulong)> { (appId, details.hcontent_file) }, DEFAULT_BRANCH, true);
            }
            else
            {
                Console.WriteLine("Unable to locate manifest ID for published file {0}", publishedFileId);
            }
        }

        public static async Task DownloadUGCAsync(uint appId, ulong ugcId)
        {
            await DownloadAppAsync(appId, new List<(uint, ulong)> { (appId, ugcId) }, DEFAULT_BRANCH, true);
        }

        public static async Task DownloadAppAsync(uint appId, List<(uint depotId, ulong manifestId)> depotManifestIds, string branch, bool isUgc)
        {
            cdnPool = new CDNClientPool(steam3, appId);

            // Load our configuration data containing the depots currently installed
            //var configPath = DEFAULT_DOWNLOAD_DIR;

            await steam3?.RequestAppInfo(appId);

            if (!await AccountHasAccess(appId))
            {
                if (await steam3.RequestFreeAppLicense(appId))
                {
                    Console.WriteLine("Obtained FreeOnDemand license for app {0}", appId);

                    // Fetch app info again in case we didn't get it fully without a license.
                    await steam3.RequestAppInfo(appId, true);
                }
                else
                {
                    var contentName = GetAppName(appId);
                    throw new ContentDownloaderException(string.Format("App {0} ({1}) is not available from this account.", appId, contentName));
                }
            }

            var hasSpecificDepots = depotManifestIds.Count > 0;
            var depotIdsFound = new List<uint>();
            var depotIdsExpected = depotManifestIds.Select(x => x.depotId).ToList();
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);

            if (isUgc)
            {
                var workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
                if (workshopDepot != 0 && !depotIdsExpected.Contains(workshopDepot))
                {
                    depotIdsExpected.Add(workshopDepot);
                    depotManifestIds = depotManifestIds.Select(pair => (workshopDepot, pair.manifestId)).ToList();
                }

                depotIdsFound.AddRange(depotIdsExpected);
            }
            else
            {
                Console.WriteLine("Using app branch: '{0}'.", branch);

                if (depots != null)
                {
                    foreach (var depotSection in depots.Children)
                    {
                        var id = INVALID_DEPOT_ID;
                        if (depotSection.Children.Count == 0)
                            continue;

                        if (!uint.TryParse(depotSection.Name, out id))
                            continue;

                        if (hasSpecificDepots && !depotIdsExpected.Contains(id))
                            continue;

                        depotIdsFound.Add(id);

                        if (!hasSpecificDepots)
                            depotManifestIds.Add((id, INVALID_MANIFEST_ID));
                    }
                }

                if (depotManifestIds.Count == 0 && !hasSpecificDepots)
                {
                    throw new ContentDownloaderException(string.Format("Couldn't find any depots to download for app {0}", appId));
                }

                if (depotIdsFound.Count < depotIdsExpected.Count)
                {
                    var remainingDepotIds = depotIdsExpected.Except(depotIdsFound);
                    throw new ContentDownloaderException(string.Format("Depot {0} not listed for app {1}", string.Join(", ", remainingDepotIds), appId));
                }
            }

            var infos = new List<DepotDownloadInfo>();

            foreach (var (depotId, manifestId) in depotManifestIds)
            {
                var info = await GetDepotInfo(depotId, appId, manifestId, branch);
                if (info != null)
                {
                    infos.Add(info);
                }
            }

            try
            {
                await DownloadSteam3Async(infos).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Console.WriteLine("App {0} was not completely downloaded.", appId);
                throw;
            }
        }

        static async Task<DepotDownloadInfo> GetDepotInfo(uint depotId, uint appId, ulong manifestId, string branch)
        {
            if (steam3 != null && appId != INVALID_APP_ID)
            {
                await steam3.RequestAppInfo(appId);
            }

            if (!await AccountHasAccess(depotId))
            {
                Console.WriteLine("Depot {0} is not available from this account.", depotId);

                return null;
            }

            if (manifestId == INVALID_MANIFEST_ID)
            {
                manifestId = await GetSteam3DepotManifest(depotId, appId, branch);
                if (manifestId == INVALID_MANIFEST_ID && !string.Equals(branch, DEFAULT_BRANCH, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("Warning: Depot {0} does not have branch named \"{1}\". Trying {2} branch.", depotId, branch, DEFAULT_BRANCH);
                    branch = DEFAULT_BRANCH;
                    manifestId = await GetSteam3DepotManifest(depotId, appId, branch);
                }

                if (manifestId == INVALID_MANIFEST_ID)
                {
                    Console.WriteLine("Depot {0} missing public subsection or manifest section.", depotId);
                    return null;
                }
            }

            await steam3.RequestDepotKey(depotId, appId);
            if (!steam3.DepotKeys.TryGetValue(depotId, out var depotKey))
            {
                Console.WriteLine("No valid depot key for {0}, unable to download.", depotId);
                return null;
            }
            else
            {
                var depotFile = Path.Combine(DEPOT_KEY_DIR, $"{depotId}.depotkey");
                if (!Directory.Exists(DEPOT_KEY_DIR))
                {
                    Directory.CreateDirectory(DEPOT_KEY_DIR);
                }
                if (!File.Exists(depotFile))
                {
                    await File.WriteAllBytesAsync(depotFile, depotKey);
                }
            }

            var uVersion = GetSteam3AppBuildNumber(appId, branch);

            if (!CreateDirectories(depotId, uVersion, out var installDir))
            {
                Console.WriteLine("Error: Unable to create install directories!");
                return null;
            }

            return new DepotDownloadInfo(depotId, appId, manifestId, branch, installDir, depotKey);
        }

        //private class ChunkMatch(ProtoManifest.ChunkData oldChunk, ProtoManifest.ChunkData newChunk)
        //{
        //    public ProtoManifest.ChunkData OldChunk { get; } = oldChunk;
        //    public ProtoManifest.ChunkData NewChunk { get; } = newChunk;
        //}

        private class DepotChunksData
        {
            public DepotDownloadInfo depotDownloadInfo;
            public DepotDownloadCounter depotCounter;
            public string depotDir;
            public ProtoManifest manifest;
            public List<ProtoManifest.ChunkData> filteredChunks;
            public HashSet<string> allChunkNames;
        }

        //private class FileStreamData
        //{
        //    public FileStream fileStream;
        //    public SemaphoreSlim fileLock;
        //    public int chunksToDownload;
        //}

        private class GlobalDownloadCounter
        {
            public ulong completeDownloadSize;
            public ulong totalBytesCompressed;
            public ulong totalBytesUncompressed;
            public ulong totalChunks;
        }

        private class DepotDownloadCounter
        {
            public ulong completeDownloadSize;
            public ulong sizeDownloaded;
            public ulong depotBytesCompressed;
            public ulong depotBytesUncompressed;
        }

        private static async Task DownloadSteam3Async(List<DepotDownloadInfo> depots)
        {
            Ansi.Progress(Ansi.ProgressState.Indeterminate);

            var cts = new CancellationTokenSource();
            cdnPool.ExhaustedToken = cts;

            var downloadCounter = new GlobalDownloadCounter();
            var depotsToDownload = new List<DepotChunksData>(depots.Count);
            var allChunkNamesAllDepots = new HashSet<string>();

            // First, fetch all the manifests for each depot (including previous manifests) and perform the initial setup
            foreach (var depot in depots)
            {
                var depotChunkData = await ProcessDepotManifestAndFiles(cts, depot, downloadCounter);

                if (depotChunkData != null)
                {
                    depotsToDownload.Add(depotChunkData);
                    allChunkNamesAllDepots.UnionWith(depotChunkData.allChunkNames);
                }

                cts.Token.ThrowIfCancellationRequested();
            }

            foreach (var depotChunkData in depotsToDownload)
            {
                await DownloadSteam3AsyncDepotFiles(cts, downloadCounter, depotChunkData, allChunkNamesAllDepots);
            }

            Ansi.Progress(Ansi.ProgressState.Hidden);

            //Console.WriteLine("Total downloaded: {0} bytes from {2} depots",
            //    downloadCounter.totalBytesCompressed, depots.Count);
        }

        private static async Task<DepotChunksData> ProcessDepotManifestAndFiles(CancellationTokenSource cts, DepotDownloadInfo depot, GlobalDownloadCounter downloadCounter)
        {
            var depotCounter = new DepotDownloadCounter();

            Console.WriteLine("Processing depot {0}", depot.DepotId);
            ProtoManifest protoManifest = null;
            var configDir = Path.Combine(depot.InstallDir, CONFIG_DIR);

            Console.Write("Downloading depot manifest... ");

            DepotManifest depotManifest = null;
            ulong manifestRequestCode = 0;
            var manifestRequestCodeExpiration = DateTime.MinValue;

            var manifestDir = Path.Combine(depotPath, $"{depot.ManifestId.ToString()}.zip");
            do
            {
                if (!File.Exists(manifestDir))
                {
                    cts.Token.ThrowIfCancellationRequested();

                    Server connection = null;

                    try
                    {
                        connection = cdnPool.GetConnection(cts.Token);

                        string cdnToken = null;
                        if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                        {
                            var result = await authTokenCallbackPromise.Task;
                            cdnToken = result.Token;
                        }

                        var now = DateTime.Now;

                        // In order to download this manifest, we need the current manifest request code
                        // The manifest request code is only valid for a specific period in time
                        if (manifestRequestCode == 0 || now >= manifestRequestCodeExpiration)
                        {
                            manifestRequestCode = await steam3.GetDepotManifestRequestCodeAsync(
                                depot.DepotId,
                                depot.AppId,
                                depot.ManifestId,
                                depot.Branch);
                            // This code will hopefully be valid for one period following the issuing period
                            manifestRequestCodeExpiration = now.Add(TimeSpan.FromMinutes(5));

                            // If we could not get the manifest code, this is a fatal error
                            if (manifestRequestCode == 0)
                            {
                                Console.WriteLine("No manifest request code was returned for {0} {1}", depot.DepotId, depot.ManifestId);
                                cts.Cancel();
                            }
                        }

                        DebugLog.WriteLine("ContentDownloader",
                            "Downloading manifest {0} from {1} with {2}",
                            depot.ManifestId,
                            connection,
                            cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                        var rawManifest = await RawClient.DownloadRawManifestAsync(
                            depot.DepotId,
                            depot.ManifestId,
                            manifestRequestCode,
                            connection,
                            cdnPool.ProxyServer,
                            cdnToken).ConfigureAwait(false);

                        await File.WriteAllBytesAsync(manifestDir, rawManifest);

                        MemoryStream ms;
                        ms = new MemoryStream(rawManifest);
                        using var zip = new ZipArchive(ms);
                        var entries = zip.Entries;

                        using var zipEntryStream = entries[0].Open();
                        depotManifest = DepotManifest.Deserialize(zipEntryStream);
                        ms.Dispose();

                        cdnPool.ReturnConnection(connection);
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Connection timeout downloading depot manifest {0} {1}. Retrying.", depot.DepotId, depot.ManifestId);
                    }
                    catch (SteamKitWebRequestException e)
                    {
                        // If the CDN returned 403, attempt to get a cdn auth if we didn't yet
                        if (e.StatusCode == HttpStatusCode.Forbidden && !steam3.CDNAuthTokens.ContainsKey((depot.DepotId, connection.Host)))
                        {
                            await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                            cdnPool.ReturnConnection(connection);

                            continue;
                        }

                        cdnPool.ReturnBrokenConnection(connection);

                        if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                        {
                            Console.WriteLine("Encountered {2} for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId, (int)e.StatusCode);
                            break;
                        }

                        if (e.StatusCode == HttpStatusCode.NotFound)
                        {
                            Console.WriteLine("Encountered 404 for depot manifest {0} {1}. Aborting.", depot.DepotId, depot.ManifestId);
                            break;
                        }

                        Console.WriteLine("Encountered error downloading depot manifest {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.StatusCode);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        cdnPool.ReturnBrokenConnection(connection);
                        Console.WriteLine("Encountered error downloading manifest for depot {0} {1}: {2}", depot.DepotId, depot.ManifestId, e.Message);
                    }
                }
                else
                {
                    Console.WriteLine("Already have manifest {0} for depot {1}.", depot.ManifestId, depot.DepotId);
                    using var filestream = new FileStream(manifestDir, FileMode.Open);
                    using var zip = new ZipArchive(filestream);
                    var entries = zip.Entries;

                    using var zipEntryStream = entries[0].Open();
                    depotManifest = DepotManifest.Deserialize(zipEntryStream);
                }
            } while (depotManifest == null);

            if (depotManifest == null)
            {
                Console.WriteLine("\nUnable to download manifest {0} for depot {1}", depot.ManifestId, depot.DepotId);
                cts.Cancel();
            }

            protoManifest = new ProtoManifest(depotManifest, depot.ManifestId);

            // Throw the cancellation exception if requested so that this task is marked failed
            cts.Token.ThrowIfCancellationRequested();

            Console.WriteLine(" Done!");

            protoManifest.Files.Sort((x, y) => string.Compare(x.FileName, y.FileName, StringComparison.Ordinal));

            //Console.WriteLine("Manifest {0} ({1})", depot.ManifestId, protoManifest.CreationTime);

            if (Config.DownloadManifestOnly)
            {
                return null;
            }

            var chunksAfterExclusions = protoManifest.Files.AsParallel().Where(f => TestIsFileIncluded(f.FileName)).SelectMany(f => f.Chunks).ToList();
            var allChunkNames = new HashSet<string>(chunksAfterExclusions.Count);
            downloadCounter.totalChunks = (ulong)chunksAfterExclusions.Count;

            var chunksAfterFiltering = new List<ProtoManifest.ChunkData>();
            // Pre-process
            chunksAfterExclusions.ForEach(chunk =>
            {
                if (!Path.Exists(Path.Combine(depot.InstallDir, BitConverter.ToString(chunk.ChunkID).Replace("-", "").ToLower())))
                {
                    chunksAfterFiltering.Add(chunk);
                    downloadCounter.completeDownloadSize += chunk.UncompressedLength;
                    depotCounter.completeDownloadSize += chunk.UncompressedLength;
                }
                else
                {
                    downloadCounter.totalChunks--;
                }
                //var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                //var fileStagingPath = Path.Combine(stagingDir, file.FileName);

                //if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                //{
                //    Directory.CreateDirectory(fileFinalPath);
                //    Directory.CreateDirectory(fileStagingPath);
                //}
                //else
                //{
                //    // Some manifests don't explicitly include all necessary directories
                //    Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath));
                //    Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath));

                //    downloadCounter.completeDownloadSize += file.TotalSize;
                //    depotCounter.completeDownloadSize += file.TotalSize;
                //}
            });

            var remainingChunkNames = new HashSet<string>(chunksAfterFiltering.Count);

            chunksAfterFiltering.ForEach(chunk =>
            {
                remainingChunkNames.Add(BitConverter.ToString(chunk.ChunkID).Replace("-", "").ToLower());
            });

            return new DepotChunksData
            {
                depotDownloadInfo = depot,
                depotCounter = depotCounter,
                depotDir = depotPath,
                manifest = protoManifest,
                filteredChunks = chunksAfterFiltering,
                allChunkNames = remainingChunkNames
            };
        }

        private static async Task DownloadSteam3AsyncDepotFiles(CancellationTokenSource cts,
            GlobalDownloadCounter downloadCounter, DepotChunksData depotChunksData, HashSet<string> allChunkNamesAllDepots)
        {
            var depot = depotChunksData.depotDownloadInfo;
            var depotCounter = depotChunksData.depotCounter;

            Console.WriteLine("Downloading depot {0}", depot.DepotId);

            //var files = depotFilesData.filteredChunks.Where(f => !f.Flags.HasFlag(EDepotFileFlag.Directory)).ToArray();
            // var networkChunkQueue = ProtoManifest.ChunkData chunk;

            //await Util.InvokeAsync(
            //    files.Select(file => new Func<Task>(async () =>
            //        await Task.Run(() => DownloadSteam3AsyncDepotFile(cts, downloadCounter, depotFilesData, file, networkChunkQueue)))),
            //    maxDegreeOfParallelism: Config.MaxDownloads
            //);

            //var networkChunkQueue = depotChunksData.filteredChunks;

            await Util.InvokeAsync(
                depotChunksData.filteredChunks.Select(q => new Func<Task>(async () =>
                    await Task.Run(() => DownloadSteam3AsyncDepotFileChunk(cts, downloadCounter, depotChunksData,
                        q)))),
                maxDegreeOfParallelism: Config.MaxDownloads
            );

            Console.WriteLine("Depot {0} - Downloaded {1} bytes", depot.DepotId, depotCounter.depotBytesCompressed);
        }

        //private static void DownloadSteam3AsyncDepotFile(
        //    CancellationTokenSource cts,
        //    GlobalDownloadCounter downloadCounter,
        //    DepotChunksData depotFilesData,
        //    ProtoManifest.FileData file,
        //    ConcurrentQueue<(FileStreamData, ProtoManifest.FileData, ProtoManifest.ChunkData)> networkChunkQueue)
        //{
        //    cts.Token.ThrowIfCancellationRequested();

        //    var depot = depotFilesData.depotDownloadInfo;
        //    var depotDownloadCounter = depotFilesData.depotCounter;
        //    ProtoManifest.FileData oldManifestFile = null;

        //    List<ProtoManifest.ChunkData> neededChunks;
        //    if (oldManifestFile != null)
        //    {
        //        neededChunks = [];

        //        var hashMatches = oldManifestFile.FileHash.SequenceEqual(file.FileHash);
        //        if (Config.VerifyAll || !hashMatches)
        //        {
        //            var matchingChunks = new List<ChunkMatch>();

        //            foreach (var chunk in file.Chunks)
        //            {
        //                var oldChunk = oldManifestFile.Chunks.FirstOrDefault(c => c.ChunkID.SequenceEqual(chunk.ChunkID));
        //                if (oldChunk != null)
        //                {
        //                    matchingChunks.Add(new ChunkMatch(oldChunk, chunk));
        //                }
        //                else
        //                {
        //                    neededChunks.Add(chunk);
        //                }
        //            }

        //            var orderedChunks = matchingChunks.OrderBy(x => x.OldChunk.Offset);

        //            var copyChunks = new List<ChunkMatch>();

        //            using (var fsOld = File.Open(fileFinalPath, FileMode.Open))
        //            {
        //                foreach (var match in orderedChunks)
        //                {
        //                    fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

        //                    var adler = Util.AdlerHash(fsOld, (int)match.OldChunk.UncompressedLength);
        //                    if (!adler.SequenceEqual(match.OldChunk.Checksum))
        //                    {
        //                        neededChunks.Add(match.NewChunk);
        //                    }
        //                    else
        //                    {
        //                        copyChunks.Add(match);
        //                    }
        //                }
        //            }

        //            if (!hashMatches || neededChunks.Count > 0)
        //            {
        //                File.Move(fileFinalPath, fileStagingPath);

        //                using (var fsOld = File.Open(fileStagingPath, FileMode.Open))
        //                {
        //                    using var fs = File.Open(fileFinalPath, FileMode.Create);
        //                    try
        //                    {
        //                        fs.SetLength((long)file.TotalSize);
        //                    }
        //                    catch (IOException ex)
        //                    {
        //                        throw new ContentDownloaderException(string.Format("Failed to resize file to expected size {0}: {1}", fileFinalPath, ex.Message));
        //                    }

        //                    foreach (var match in copyChunks)
        //                    {
        //                        fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

        //                        var tmp = new byte[match.OldChunk.UncompressedLength];
        //                        fsOld.Read(tmp, 0, tmp.Length);

        //                        fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
        //                        fs.Write(tmp, 0, tmp.Length);
        //                    }
        //                }

        //                File.Delete(fileStagingPath);
        //            }
        //        }
        //    }
        //    else
        //    {
        //        // No old manifest or file not in old manifest. We must validate.

        //        using var fs = File.Open(fileFinalPath, FileMode.Open);
        //        if ((ulong)fi.Length != file.TotalSize)
        //        {
        //            try
        //            {
        //                fs.SetLength((long)file.TotalSize);
        //            }
        //            catch (IOException ex)
        //            {
        //                throw new ContentDownloaderException(string.Format("Failed to allocate file {0}: {1}", fileFinalPath, ex.Message));
        //            }
        //        }

        //        Console.WriteLine("Validating {0}", fileFinalPath);
        //        neededChunks = Util.ValidateSteam3FileChecksums(fs, [.. file.Chunks.OrderBy(x => x.Offset)]);
        //    }

        //    if (neededChunks.Count == 0)
        //    {
        //        lock (depotDownloadCounter)
        //        {
        //            depotDownloadCounter.sizeDownloaded += file.TotalSize;
        //            Console.WriteLine("{0,6:#00.00}% {1}", (depotDownloadCounter.sizeDownloaded / (float)depotDownloadCounter.completeDownloadSize) * 100.0f, fileFinalPath);
        //        }

        //        lock (downloadCounter)
        //        {
        //            downloadCounter.completeDownloadSize -= file.TotalSize;
        //        }

        //        return;
        //    }

        //    var sizeOnDisk = (file.TotalSize - (ulong)neededChunks.Select(x => (long)x.UncompressedLength).Sum());
        //    lock (depotDownloadCounter)
        //    {
        //        depotDownloadCounter.sizeDownloaded += sizeOnDisk;
        //    }

        //    lock (downloadCounter)
        //    {
        //        downloadCounter.completeDownloadSize -= sizeOnDisk;
        //    }

        //    var fileIsExecutable = file.Flags.HasFlag(EDepotFileFlag.Executable);
        //    if (fileIsExecutable && (!fileDidExist || oldManifestFile == null || !oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable)))
        //    {
        //        PlatformUtilities.SetExecutable(fileFinalPath, true);
        //    }
        //    else if (!fileIsExecutable && oldManifestFile != null && oldManifestFile.Flags.HasFlag(EDepotFileFlag.Executable))
        //    {
        //        PlatformUtilities.SetExecutable(fileFinalPath, false);
        //    }

        //    var fileStreamData = new FileStreamData
        //    {
        //        fileStream = null,
        //        fileLock = new SemaphoreSlim(1),
        //        chunksToDownload = neededChunks.Count
        //    };

        //    foreach (var chunk in neededChunks)
        //    {
        //        networkChunkQueue.Enqueue((fileStreamData, file, chunk));
        //    }
        //}

        private static async Task DownloadSteam3AsyncDepotFileChunk(
            CancellationTokenSource cts,
            GlobalDownloadCounter downloadCounter,
            DepotChunksData depotFilesData,
            //ProtoManifest.FileData file,
            //FileStreamData fileStreamData,
            ProtoManifest.ChunkData chunk)
        {
            cts.Token.ThrowIfCancellationRequested();

            var depot = depotFilesData.depotDownloadInfo;
            var depotDownloadCounter = depotFilesData.depotCounter;

            var chunkID = Convert.ToHexString(chunk.ChunkID).ToLowerInvariant();

            var data = new DepotManifest.ChunkData
            {
                ChunkID = chunk.ChunkID,
                //Checksum = BitConverter.ToUInt32(chunk.Checksum),
                //Offset = chunk.Offset,
                CompressedLength = chunk.CompressedLength,
                UncompressedLength = chunk.UncompressedLength
            };

            //byte[] chunkBuffer = null;
            var chunkSize = 0;
            var chunkBuffer = ArrayPool<byte>.Shared.Rent((int)data.CompressedLength);
            var chunkDir = Path.Combine(depot.InstallDir, chunkID);

            try
            {
                do
                {
                    cts.Token.ThrowIfCancellationRequested();

                    Server connection = null;

                    try
                    {
                        connection = cdnPool.GetConnection(cts.Token);

                        string cdnToken = null;
                        if (steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise))
                        {
                            var result = await authTokenCallbackPromise.Task;
                            cdnToken = result.Token;
                        }

                        DebugLog.WriteLine("ContentDownloader", "Downloading chunk {0} from {1} with {2}", chunkID, connection, cdnPool.ProxyServer != null ? cdnPool.ProxyServer : "no proxy");
                        chunkBuffer = await RawClient.DownloadRawChunkAsync(
                            depot.DepotId,
                            data,
                            connection,
                            chunkBuffer,
                            cdnPool.ProxyServer,
                            cdnToken).ConfigureAwait(false);

                        cdnPool.ReturnConnection(connection);

                        break;
                    }
                    catch (TaskCanceledException)
                    {
                        Console.WriteLine("Connection timeout downloading chunk {0}", chunkID);
                    }
                    catch (SteamKitWebRequestException e)
                    {
                        // If the CDN returned 403, attempt to get a cdn auth if we didn't yet,
                        // if auth task already exists, make sure it didn't complete yet, so that it gets awaited above
                        if (e.StatusCode == HttpStatusCode.Forbidden &&
                            (!steam3.CDNAuthTokens.TryGetValue((depot.DepotId, connection.Host), out var authTokenCallbackPromise) || !authTokenCallbackPromise.Task.IsCompleted))
                        {
                            await steam3.RequestCDNAuthToken(depot.AppId, depot.DepotId, connection);

                            cdnPool.ReturnConnection(connection);

                            continue;
                        }

                        cdnPool.ReturnBrokenConnection(connection);

                        if (e.StatusCode == HttpStatusCode.Unauthorized || e.StatusCode == HttpStatusCode.Forbidden)
                        {
                            Console.WriteLine("Encountered {1} for chunk {0}. Aborting.", chunkID, (int)e.StatusCode);
                            break;
                        }

                        Console.WriteLine("Encountered error downloading chunk {0}: {1}", chunkID, e.StatusCode);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception e)
                    {
                        cdnPool.ReturnBrokenConnection(connection);
                        Console.WriteLine("Encountered unexpected error downloading chunk {0}: {1}", chunkID, e.Message);
                    }
                } while (chunkBuffer == null);

                if (chunkBuffer == null)
                {
                    Console.WriteLine("Failed to find any server with chunk {0} for depot {1}. Aborting.", chunkID, depot.DepotId);
                    cts.Cancel();
                }

                chunkSize = chunkBuffer.Length;

                // Throw the cancellation exception if requested so that this task is marked failed
                cts.Token.ThrowIfCancellationRequested();

                try
                {
                    await File.WriteAllBytesAsync(chunkDir, chunkBuffer);
                }
                finally
                {
                    chunkBuffer = null;
                    ArrayPool<byte>.Shared.Return(chunkBuffer);
                }
                //try
                //{
                //    await fileStreamData.fileLock.WaitAsync().ConfigureAwait(false);

                //    if (fileStreamData.fileStream == null)
                //    {
                //        var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                //        fileStreamData.fileStream = File.Open(fileFinalPath, FileMode.Open);
                //    }

                //    fileStreamData.fileStream.Seek((long)data.Offset, SeekOrigin.Begin);
                //    await fileStreamData.fileStream.WriteAsync(chunkBuffer.AsMemory(0, written), cts.Token);
                //}
                //finally
                //{
                //    fileStreamData.fileLock.Release();
                //}
            }
            finally
            {
            }

            //var remainingChunks = Interlocked.Decrement(ref fileStreamData.chunksToDownload);
            //if (remainingChunks == 0)
            //{
            //    fileStreamData.fileStream?.Dispose();
            //    fileStreamData.fileLock.Dispose();
            //}

            ulong sizeDownloaded = 0;
            lock (depotDownloadCounter)
            {
                sizeDownloaded = depotDownloadCounter.sizeDownloaded + (ulong)chunkSize;
                depotDownloadCounter.sizeDownloaded = sizeDownloaded;
                depotDownloadCounter.depotBytesCompressed += chunk.CompressedLength;
            }

            lock (downloadCounter)
            {
                downloadCounter.totalBytesCompressed += chunk.CompressedLength;

                Ansi.Progress(downloadCounter.totalBytesCompressed, downloadCounter.completeDownloadSize);
            }

            if (downloadCounter.totalChunks == 0)
            {
                //var fileFinalPath = Path.Combine(depot.InstallDir, file.FileName);
                //Console.WriteLine("{0,6:#00.00}% {1}", (sizeDownloaded / (float)depotDownloadCounter.completeDownloadSize) * 100.0f, fileFinalPath);
            }
        }
    }
}

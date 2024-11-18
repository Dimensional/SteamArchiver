// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SteamKit2;
using static DepotDownloader.ContentDownloader;

namespace DepotDownloader
{
    class Program
    {
        static async Task<int> Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintVersion();
                PrintUsage();

                if (OperatingSystem.IsWindowsVersionAtLeast(5, 0))
                {
                    PlatformUtilities.VerifyConsoleLaunch();
                }

                return 0;
            }

            Ansi.Init();

            DebugLog.Enabled = false;

            AccountSettingsStore.LoadFromFile("account.config");

            #region Common Options

            // Not using HasParameter because it is case insensitive
            if (args.Length == 1 && (args[0] == "-V" || args[0] == "--version"))
            {
                PrintVersion(true);
                return 0;
            }

            if (HasParameter(args, "-debug"))
            {
                PrintVersion(true);

                DebugLog.Enabled = true;
                DebugLog.AddListener((category, message) =>
                {
                    Console.WriteLine("[{0}] {1}", category, message);
                });

                var httpEventListener = new HttpDiagnosticEventListener();
            }

            var username = GetParameter<string>(args, "-username") ?? GetParameter<string>(args, "-user");
            var password = GetParameter<string>(args, "-password") ?? GetParameter<string>(args, "-pass");
            ContentDownloader.Config.RememberPassword = HasParameter(args, "-remember-password");
            ContentDownloader.Config.UseQrCode = HasParameter(args, "-qr");

            ContentDownloader.Config.DownloadManifestOnly = HasParameter(args, "-manifest-only");

            var cellId = GetParameter(args, "-cellid", -1);
            if (cellId == -1)
            {
                cellId = 0;
            }

            ContentDownloader.Config.CellID = cellId;

            ContentDownloader.Config.VerifyAll = HasParameter(args, "-verify-all") || HasParameter(args, "-verify_all") || HasParameter(args, "-validate");
            ContentDownloader.Config.MaxServers = GetParameter(args, "-max-servers", 20);
            ContentDownloader.Config.MaxDownloads = GetParameter(args, "-max-downloads", 8);
            ContentDownloader.Config.MaxServers = Math.Max(ContentDownloader.Config.MaxServers, ContentDownloader.Config.MaxDownloads);
            ContentDownloader.Config.LoginID = HasParameter(args, "-loginid") ? GetParameter<uint>(args, "-loginid") : null;

            #endregion

            List<(uint appId, uint? depotId, ulong? manifestId, string branch)> appTuples;

            if (HasParameter(args, "-csv"))
            {
                var csvFilePath = GetParameter<string>(args, "-csv");
                appTuples = ReadCsvFile(csvFilePath);
            }
            else
            {
                var appIndices = Enumerable.Range(0, args.Length)
                                            .Where(i => args[i].Equals("-app", StringComparison.OrdinalIgnoreCase))
                                            .ToList();

                if (appIndices.Count == 0)
                {
                    Console.WriteLine("Error: -app requires at least 1 value!");
                    return 1;
                }

                appTuples = new List<(uint appId, uint? depotId, ulong? manifestId, string branch)>();

                foreach (var index in appIndices)
                {
                    var appParamsList = args.Skip(index + 1).Take(4).ToList();
                    var myTuple = (
                        appId: uint.TryParse(appParamsList.ElementAtOrDefault(0), out var appId) ? appId : ContentDownloader.INVALID_APP_ID,
                        depotId: uint.TryParse(appParamsList.ElementAtOrDefault(1), out var depotId) ? depotId : (uint?)null,
                        manifestId: ulong.TryParse(appParamsList.ElementAtOrDefault(2), out var manifestId) ? manifestId : (ulong?)null,
                        branch: appParamsList.ElementAtOrDefault(3) ?? ContentDownloader.DEFAULT_BRANCH
                    );

                    if (myTuple.appId == ContentDownloader.INVALID_APP_ID)
                    {
                        Console.WriteLine("Error: -app not specified correctly!");
                        return 1;
                    }

                    appTuples.Add(myTuple);
                }
            }

            if (InitializeSteam(username, password))
            {
                foreach (var appTuple in appTuples)
                {
                    var appId = appTuple.appId;
                    var depotIdList = appTuple.depotId;
                    var manifestIdList = appTuple.manifestId;
                    var branch = appTuple.branch;

                    var pubFile = GetParameter(args, "-pubfile", ContentDownloader.INVALID_MANIFEST_ID);
                    var ugcId = GetParameter(args, "-ugc", ContentDownloader.INVALID_MANIFEST_ID);
                    if ((pubFile != ContentDownloader.INVALID_MANIFEST_ID || ugcId != ContentDownloader.INVALID_MANIFEST_ID) && depotIdList != null)
                    {
                        Console.WriteLine("Error: -depot cannot be used with -pubfile or -ugc");
                        return 1;
                    }
                    if (pubFile != ContentDownloader.INVALID_MANIFEST_ID)
                    {
                        #region Pubfile Downloading

                        try
                        {
                            await ContentDownloader.DownloadPubfileAsync(appId, pubFile).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (
                            ex is ContentDownloaderException
                            || ex is OperationCanceledException)
                        {
                            Console.WriteLine(ex.Message);
                            return 1;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                            throw;
                        }
                        finally
                        {
                            ContentDownloader.ShutdownSteam3();
                        }

                        #endregion
                    }
                    else if (ugcId != ContentDownloader.INVALID_MANIFEST_ID)
                    {
                        #region UGC Downloading

                        try
                        {
                            await ContentDownloader.DownloadUGCAsync(appId, ugcId).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (
                            ex is ContentDownloaderException
                            || ex is OperationCanceledException)
                        {
                            Console.WriteLine(ex.Message);
                            return 1;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                            throw;
                        }
                        finally
                        {
                            ContentDownloader.ShutdownSteam3();
                        }

                        #endregion
                    }
                    else
                    {
                        #region App downloading

                        ContentDownloader.Config.BetaPassword = GetParameter<string>(args, "-betapassword");

                        var depotManifestIds = new List<(uint, ulong)>();
                        var isUGC = false;

                        depotManifestIds.Add((depotIdList.Value, manifestIdList ?? ContentDownloader.INVALID_MANIFEST_ID));

                        try
                        {
                            await ContentDownloader.DownloadAppAsync(appId, depotManifestIds, branch, isUGC).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (
                            ex is ContentDownloaderException
                            || ex is OperationCanceledException)
                        {
                            Console.WriteLine(ex.Message);
                            return 1;
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("Download failed to due to an unhandled exception: {0}", e.Message);
                            throw;
                        }
                        //catch (Http401Exception ex)
                        //{
                        //    Console.WriteLine("Error: {0}", ex.Message);
                        //    continue;
                        //}
                        finally
                        {
                            if (appTuple.Equals(appTuples.Last()))
                            {
                                ContentDownloader.ShutdownSteam3();
                            }
                        }
                    }

                    #endregion
                }
            }
            else
            {
                Console.WriteLine("Error: InitializeSteam failed");
                return 1;
            }
            return 0;
        }

        static bool InitializeSteam(string username, string password)
        {
            if (!ContentDownloader.Config.UseQrCode)
            {
                if (username != null && password == null && (!ContentDownloader.Config.RememberPassword || !AccountSettingsStore.Instance.LoginTokens.ContainsKey(username)))
                {
                    do
                    {
                        Console.Write("Enter account password for \"{0}\": ", username);
                        if (Console.IsInputRedirected)
                        {
                            password = Console.ReadLine();
                        }
                        else
                        {
                            // Avoid console echoing of password
                            password = Util.ReadPassword();
                        }

                        Console.WriteLine();
                    } while (string.Empty == password);
                }
                else if (username == null)
                {
                    Console.WriteLine("No username given. Using anonymous account with dedicated server subscription.");
                }
            }

            return ContentDownloader.InitializeSteam3(username, password);
        }

        static int IndexOfParam(string[] args, string param)
        {
            for (var x = 0; x < args.Length; ++x)
            {
                if (args[x].Equals(param, StringComparison.OrdinalIgnoreCase))
                    return x;
            }

            return -1;
        }

        static bool HasParameter(string[] args, string param)
        {
            return IndexOfParam(args, param) > -1;
        }

        static T GetParameter<T>(string[] args, string param, T defaultValue = default)
        {
            var index = IndexOfParam(args, param);

            if (index == -1 || index == (args.Length - 1))
                return defaultValue;

            var strParam = args[index + 1];

            var converter = TypeDescriptor.GetConverter(typeof(T));
            if (converter != null)
            {
                return (T)converter.ConvertFromString(strParam);
            }

            return default;
        }

        static List<T> GetParameterList<T>(string[] args, string param)
        {
            var list = new List<T>();
            var index = IndexOfParam(args, param);

            if (index == -1 || index == (args.Length - 1))
                return list;

            index++;

            while (index < args.Length)
            {
                var strParam = args[index];

                if (strParam[0] == '-') break;

                var converter = TypeDescriptor.GetConverter(typeof(T));
                if (converter != null)
                {
                    list.Add((T)converter.ConvertFromString(strParam));
                }

                index++;
            }

            return list;
        }

        static void PrintUsage()
        {
            // Do not use tabs to align parameters here because tab size may differ
            Console.WriteLine();
            Console.WriteLine("Usage: downloading one or all depots for an app:");
            Console.WriteLine("       depotdownloader -app <id> [-depot <id> [-manifest <id>]]");
            Console.WriteLine("                       [-username <username> [-password <password>]] [other options]");
            Console.WriteLine();
            Console.WriteLine("Usage: downloading a workshop item using pubfile id");
            Console.WriteLine("       depotdownloader -app <id> -pubfile <id> [-username <username> [-password <password>]]");
            Console.WriteLine("Usage: downloading a workshop item using ugc id");
            Console.WriteLine("       depotdownloader -app <id> -ugc <id> [-username <username> [-password <password>]]");
            Console.WriteLine();
            Console.WriteLine("Parameters:");
            Console.WriteLine("  -csv <file>              - Reads the contents of a CSV file and passes the data for downloading.");
            Console.WriteLine();
            Console.WriteLine("  -app <#>                 - the AppID to download.");
            Console.WriteLine("  -depot <#>               - the DepotID to download.");
            Console.WriteLine("  -manifest <id>           - manifest id of content to download (requires -depot, default: current for branch).");
            Console.WriteLine($"  -beta <branchname>       - download from specified branch if available (default: {ContentDownloader.DEFAULT_BRANCH}).");
            Console.WriteLine("  -betapassword <pass>     - branch password if applicable.");
            Console.WriteLine();
            Console.WriteLine("  -ugc <#>                 - the UGC ID to download.");
            Console.WriteLine("  -pubfile <#>             - the PublishedFileId to download. (Will automatically resolve to UGC id)");
            Console.WriteLine();
            Console.WriteLine("  -username <user>         - the username of the account to login to for restricted content.");
            Console.WriteLine("  -password <pass>         - the password of the account to login to for restricted content.");
            Console.WriteLine("  -remember-password       - if set, remember the password for subsequent logins of this user.");
            Console.WriteLine("                             use -username <username> -remember-password as login credentials.");
            Console.WriteLine();
            Console.WriteLine("  -validate                - include checksum verification of files already downloaded");
            Console.WriteLine("  -manifest-only           - downloads a human readable manifest for any depots that would be downloaded.");
            Console.WriteLine("  -cellid <#>              - the overridden CellID of the content server to download from.");
            Console.WriteLine("  -max-servers <#>         - maximum number of content servers to use. (default: 20).");
            Console.WriteLine("  -max-downloads <#>       - maximum number of chunks to download concurrently. (default: 8).");
            Console.WriteLine("  -loginid <#>             - a unique 32-bit integer Steam LogonID in decimal, required if running multiple instances of DepotDownloader concurrently.");
        }

        static void PrintVersion(bool printExtra = false)
        {
            var version = typeof(Program).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>().InformationalVersion;
            Console.WriteLine($"DepotDownloader v{version}");

            if (!printExtra)
            {
                return;
            }

            Console.WriteLine($"Runtime: {RuntimeInformation.FrameworkDescription} on {RuntimeInformation.OSDescription}");
        }

        static List<(uint appId, uint? depotId, ulong? manifestId, string branch)> ReadCsvFile(string filePath)
        {
            var appTuples = new List<(uint appId, uint? depotId, ulong? manifestId, string branch)>();

            using (var reader = new StreamReader(filePath))
            using (var csv = new CsvHelper.CsvReader(reader, CultureInfo.InvariantCulture))
            {
                csv.Read();
                csv.ReadHeader();
                while (csv.Read())
                {
                    var appId = csv.GetField<uint>("AppID");
                    var depotId = csv.GetField<uint?>("DepotID");
                    var manifestId = csv.GetField<ulong?>("ManifestID");
                    var branch = csv.GetField<string>("Branch") ?? ContentDownloader.DEFAULT_BRANCH;

                    appTuples.Add((appId, depotId, manifestId, branch));
                }
            }

            return appTuples;
        }
    }
}

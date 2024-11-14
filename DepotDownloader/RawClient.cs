// This file is subject to the terms and conditions defined
// in file 'LICENSE', which is part of this source code package.

using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using SteamKit2;
using SteamKit2.CDN;

namespace DepotDownloader
{
    /// <summary>
    /// The <see cref="RawClient"/> class is used for downloading game content from the Steam servers.
    /// </summary>
    public sealed class RawClient : IDisposable
    {
        HttpClient httpClient;

        /// <summary>
        /// Default timeout to use when making requests
        /// </summary>
        public static TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(10);
        /// <summary>
        /// Default timeout to use when reading the response body
        /// </summary>
        public static TimeSpan ResponseBodyTimeout { get; set; } = TimeSpan.FromSeconds(60);


        /// <summary>
        /// Initializes a new instance of the <see cref="Client"/> class.
        /// </summary>
        /// <param name="steamClient">
        /// The <see cref="SteamClient"/> this instance will be associated with.
        /// The SteamClient instance must be connected and logged onto Steam.</param>
        public RawClient()
        {
            //ArgumentNullException.ThrowIfNull(steamClient);

            this.httpClient = new HttpClient();
        }

        /// <summary>
        /// Disposes of this object.
        /// </summary>
        public void Dispose()
        {
            httpClient.Dispose();
        }

        /// <summary>
        /// Downloads the depot manifest specified by the given manifest ID.
        /// </summary>
        /// <param name="depotId">The id of the depot being accessed.</param>
        /// <param name="manifestId">The unique identifier of the manifest to be downloaded.</param>
        /// <param name="manifestRequestCode">The manifest request code for the manifest that is being downloaded.</param>
        /// <param name="server">The content server to connect to.</param>
        /// <param name="proxyServer">Optional content server marked as UseAsProxy which transforms the request.</param>
        /// <param name="cdnAuthToken">CDN auth token for CDN content server endpoints if necessary. Get one with <see cref="SteamContent.GetCDNAuthToken"/>.</param>
        /// <returns>A <see cref="byte[]"/> instance that contains information about the files present within a depot.</returns>
        /// <exception cref="System.ArgumentNullException"><see ref="server"/> was null.</exception>
        /// <exception cref="HttpRequestException">An network error occurred when performing the request.</exception>
        /// <exception cref="SteamKitWebRequestException">A network error occurred when performing the request.</exception>
        public async Task<byte[]> DownloadRawManifestAsync(uint depotId, ulong manifestId, ulong manifestRequestCode, Server server, Server? proxyServer = null, string? cdnAuthToken = null)
        {
            ArgumentNullException.ThrowIfNull(server);

            const uint MANIFEST_VERSION = 5;
            string url;

            if (manifestRequestCode > 0)
            {
                url = $"depot/{depotId}/manifest/{manifestId}/{MANIFEST_VERSION}/{manifestRequestCode}";
            }
            else
            {
                url = $"depot/{depotId}/manifest/{manifestId}/{MANIFEST_VERSION}";
            }

            using var request = new HttpRequestMessage(HttpMethod.Get, BuildRawCommand(server, url, cdnAuthToken, proxyServer));

            using var cts = new CancellationTokenSource();
            cts.CancelAfter(RequestTimeout);

            try
            {
                using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw new SteamKitWebRequestException($"Response status code does not indicate success: {response.StatusCode:D} ({response.ReasonPhrase}).", response);
                }

                cts.CancelAfter(ResponseBodyTimeout);

                var content = await response.Content.ReadAsByteArrayAsync();
                return content;
            }
            catch (Exception ex)
            {
                DebugLog.WriteLine(nameof(SteamKit2.CDN), $"Failed to download manifest {request.RequestUri}: {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Downloads the specified depot chunk, and optionally processes the chunk and verifies the checksum if the depot decryption key has been provided.
        /// </summary>
        /// <remarks>
        /// This function will also validate the length of the downloaded chunk with the value of <see cref="DepotManifest.ChunkData.CompressedLength"/>,
        /// if it has been assigned a value.
        /// </remarks>
        /// <param name="depotId">The id of the depot being accessed.</param>
        /// <param name="chunk">
        /// A <see cref="DepotManifest.ChunkData"/> instance that represents the chunk to download.
        /// This value should come from a manifest downloaded with <see cref="o:DownloadManifestAsync"/>.
        /// </param>
        /// <returns>The total number of bytes written to <paramref name="destination" />.</returns>
        /// <param name="server">The content server to connect to.</param>
        /// <param name="destination">
        /// The buffer to receive the chunk data. If <paramref name="depotKey"/> is provided, this will be the decompressed buffer.
        /// Allocate or rent a buffer that is equal or longer than <see cref="DepotManifest.ChunkData.UncompressedLength"/>
        /// </param>
        /// <param name="proxyServer">Optional content server marked as UseAsProxy which transforms the request.</param>
        /// <param name="cdnAuthToken">CDN auth token for CDN content server endpoints if necessary. Get one with <see cref="SteamContent.GetCDNAuthToken"/>.</param>
        /// <exception cref="System.ArgumentNullException">chunk's <see cref="DepotManifest.ChunkData.ChunkID"/> was null.</exception>
        /// <exception cref="System.IO.InvalidDataException">Thrown if the downloaded data does not match the expected length.</exception>
        /// <exception cref="HttpRequestException">An network error occurred when performing the request.</exception>
        /// <exception cref="SteamKitWebRequestException">A network error occurred when performing the request.</exception>
        public async Task<byte[]> DownloadRawChunkAsync(uint depotId, DepotManifest.ChunkData chunk, Server server, byte[] destination, Server? proxyServer = null, string? cdnAuthToken = null)
        {
            ArgumentNullException.ThrowIfNull(server);
            ArgumentNullException.ThrowIfNull(chunk);
            ArgumentNullException.ThrowIfNull(destination);

            if (chunk.ChunkID == null)
            {
                throw new ArgumentException($"Chunk must have a {nameof(DepotManifest.ChunkData.ChunkID)}.", nameof(chunk));
            }

            var chunkID = Util.EncodeHexString(chunk.ChunkID);
            var url = $"depot/{depotId}/chunk/{chunkID}";

            using var request = new HttpRequestMessage(HttpMethod.Get, BuildRawCommand(server, url, cdnAuthToken, proxyServer));

            using var cts = new CancellationTokenSource();
            cts.CancelAfter(RequestTimeout);

            try
            {
                using var response = await httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);

                if (!response.IsSuccessStatusCode)
                {
                    throw new SteamKitWebRequestException($"Response status code does not indicate success: {response.StatusCode:D} ({response.ReasonPhrase}).", response);
                }

                var content = await response.Content.ReadAsByteArrayAsync(cts.Token);
                return content;
            }

            catch (Exception ex)
            {
                DebugLog.WriteLine(nameof(SteamKit2.CDN), $"Failed to download a depot chunk {request.RequestUri}: {ex.Message}");
                throw;
            }
        }

        static Uri BuildRawCommand(Server server, string command, string? query, Server? proxyServer)
        {
            var uriBuilder = new UriBuilder
            {
                Scheme = server.Protocol == Server.ConnectionProtocol.HTTP ? "http" : "https",
                Host = server.VHost,
                Port = server.Port,
                Path = command,
                Query = query ?? string.Empty,
            };

            if (proxyServer != null && proxyServer.UseAsProxy && proxyServer.ProxyRequestPathTemplate != null)
            {
                var pathTemplate = proxyServer.ProxyRequestPathTemplate;
                pathTemplate = pathTemplate.Replace("%host%", uriBuilder.Host, StringComparison.Ordinal);
                pathTemplate = pathTemplate.Replace("%path%", $"/{uriBuilder.Path}", StringComparison.Ordinal);
                uriBuilder.Scheme = proxyServer.Protocol == Server.ConnectionProtocol.HTTP ? "http" : "https";
                uriBuilder.Host = proxyServer.VHost;
                uriBuilder.Port = proxyServer.Port;
                uriBuilder.Path = pathTemplate;
            }

            return uriBuilder.Uri;
        }
    }
}

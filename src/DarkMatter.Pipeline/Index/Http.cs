// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;

namespace DarkMatter.Pipeline.Index;

/// <summary>A request that failed for good: an HTTP error that retrying does not fix, or every attempt failed.</summary>
internal sealed class FetchException(string message) : Exception(message);

/// <summary>
/// GitHub's API rate limit was reached. Not retried: the limit resets at <see cref="Reset"/>
/// (unauthenticated: 60 API calls per hour).
/// </summary>
internal sealed class RateLimitException(string message, DateTimeOffset? reset) : Exception(message) {
    public DateTimeOffset? Reset { get; } = reset;
}

/// <summary>
/// HTTPS GETs with retries. Network errors, timeouts and server errors are retried with a growing
/// pause; other HTTP errors are not. A rate-limit response is retried only when GitHub asks for a
/// short wait, else it stops the run. Downloads stream to disk with a size limit counted in bytes
/// received, and a read that stalls for the timeout fails.
/// </summary>
internal sealed class Http : IDisposable {
    // A generic client name: nothing that identifies the user or the machine.
    const string UserAgent = "darkmatter-pipeline";
    static readonly TimeSpan MaxRateLimitWait = TimeSpan.FromSeconds(60);

    readonly HttpClient client;
    readonly int attempts;
    readonly TimeSpan pause;
    readonly TimeSpan timeout;

    /// <param name="attempts">Tries per request.</param>
    /// <param name="pause">Pause after the first failure; the n-th failure waits n times as long.</param>
    /// <param name="timeout">Limit for connecting and receiving the headers, and for each read of the body.</param>
    public Http(int attempts, TimeSpan pause, TimeSpan timeout) {
        this.attempts = attempts;
        this.pause = pause;
        this.timeout = timeout;
        // Redirects are followed (release assets redirect to a download host), never from HTTPS to HTTP.
        client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = true, MaxAutomaticRedirections = 10, ConnectTimeout = timeout }) {
            Timeout = Timeout.InfiniteTimeSpan,
        };
        client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue(UserAgent, null));
    }

    public void Dispose() => client.Dispose();

    /// <summary>The JSON document at <paramref name="url"/> (a GitHub API or raw-content URL).</summary>
    public async Task<JsonDocument> GetJson(string url, long maxBytes = 64 << 20) {
        using var body = new MemoryStream();
        await Get(url, body, maxBytes, api: true);
        body.Position = 0;
        try {
            return JsonDocument.Parse(body);
        } catch (JsonException e) {
            throw new FetchException($"{url}: malformed JSON ({e.Message})");
        }
    }

    /// <summary>
    /// Downloads <paramref name="url"/> to <paramref name="path"/> (through ".NAME.part" next to it,
    /// so the file exists only when complete; the leading dot keeps it apart from asset names,
    /// which start with a letter or digit). Returns its size and SHA-256 (lowercase hex).
    /// </summary>
    public async Task<(long Size, string Sha256)> Download(string url, string path, long maxBytes) {
        var tmp = Path.Join(Path.GetDirectoryName(path), "." + Path.GetFileName(path) + ".part");
        try {
            string sha;
            long size;
            using (var file = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256)) {
                var sink = new HashingStream(file, hash);
                await Get(url, sink, maxBytes, api: false);
                size = sink.Written;
                sha = Convert.ToHexStringLower(hash.GetHashAndReset());
            }
            File.Move(tmp, path, overwrite: true);
            return (size, sha);
        } finally {
            File.Delete(tmp);
        }
    }

    async Task Get(string url, Stream sink, long maxBytes, bool api) {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new FetchException($"not an HTTPS URL: {Text.Quote(url)}");
        for (int attempt = 1; ; attempt++) {
            string problem;
            TimeSpan? wait = null;
            try {
                using var request = new HttpRequestMessage(HttpMethod.Get, uri);
                if (api) request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
                using var headers = new CancellationTokenSource(timeout);
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, headers.Token);
                if (response.IsSuccessStatusCode) {
                    if (response.Content.Headers.ContentLength > maxBytes)
                        throw new FetchException($"{url}: {response.Content.Headers.ContentLength} bytes, over the {maxBytes}-byte limit");
                    sink.SetLength(0);
                    await Copy(await response.Content.ReadAsStreamAsync(headers.Token), sink, maxBytes, url);
                    return;
                }
                var code = (int)response.StatusCode;
                if (RateLimit(response) is { } limit) {
                    if (limit.Wait is { } w && w <= MaxRateLimitWait && attempt < attempts) {
                        wait = w > TimeSpan.Zero ? w : TimeSpan.FromSeconds(1);
                        problem = $"rate limited, retrying in {w.TotalSeconds:0} s";
                    } else {
                        throw new RateLimitException(
                            "GitHub rate limit reached" + (limit.Reset is { } r ? $"; it resets at {r.ToLocalTime():yyyy-MM-dd HH:mm:ss}" : "") + "; re-run then to resume",
                            limit.Reset);
                    }
                } else if (code is >= 500 or 408 or 429) {
                    problem = $"HTTP {code}";
                } else {
                    throw new FetchException($"{url}: HTTP {code} {response.ReasonPhrase}");
                }
            } catch (Exception e) when (e is HttpRequestException or IOException or OperationCanceledException) {
                problem = e is OperationCanceledException ? "timed out" : Describe(e);
            }
            if (attempt >= attempts) throw new FetchException($"{url}: {problem} (after {attempts} attempts)");
            await Task.Delay(wait ?? pause * attempt);
        }
    }

    /// <summary>The message of <paramref name="e"/> and of the exceptions inside it ("could not connect: certificate rejected").</summary>
    static string Describe(Exception e) {
        var parts = new List<string>();
        for (Exception? x = e; x != null; x = x.InnerException) parts.Add(x.Message.TrimEnd('.'));
        return string.Join(": ", parts.Distinct());
    }

    /// <summary>A rate-limit response: 403 or 429 with no calls left or a Retry-After header.</summary>
    static (TimeSpan? Wait, DateTimeOffset? Reset)? RateLimit(HttpResponseMessage response) {
        if (response.StatusCode is not (HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests)) return null;
        var remaining = Header(response, "x-ratelimit-remaining");
        var retryAfter = response.Headers.RetryAfter?.Delta;
        if (remaining != "0" && retryAfter == null) return null;
        DateTimeOffset? reset = long.TryParse(Header(response, "x-ratelimit-reset"), NumberStyles.None, CultureInfo.InvariantCulture, out var s)
            ? DateTimeOffset.FromUnixTimeSeconds(s)
            : null;
        return (retryAfter ?? (reset is { } r ? r - DateTimeOffset.UtcNow : null), reset);
    }

    static string? Header(HttpResponseMessage response, string name) =>
        response.Headers.TryGetValues(name, out var v) ? v.FirstOrDefault() : null;

    async Task Copy(Stream body, Stream sink, long maxBytes, string url) {
        var buffer = new byte[1 << 16];
        long total = 0;
        while (true) {
            using var read = new CancellationTokenSource(timeout);
            int n = await body.ReadAsync(buffer, read.Token);
            if (n == 0) return;
            total += n;
            if (total > maxBytes) throw new FetchException($"{url}: over the {maxBytes}-byte limit");
            await sink.WriteAsync(buffer.AsMemory(0, n), read.Token);
        }
    }

    /// <summary>Writes through to a file and hashes what was written.</summary>
    sealed class HashingStream(FileStream file, IncrementalHash hash) : Stream {
        public long Written { get; private set; }

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => Written;
        public override long Position { get => Written; set => throw new NotSupportedException(); }

        // A retried download starts over.
        public override void SetLength(long value) {
            if (value != 0) throw new NotSupportedException();
            file.SetLength(0);
            file.Position = 0;
            hash.GetHashAndReset();
            Written = 0;
        }

        public override void Write(byte[] buffer, int offset, int count) => Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer) {
            hash.AppendData(buffer);
            file.Write(buffer);
            Written += buffer.Length;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default) {
            hash.AppendData(buffer.Span);
            await file.WriteAsync(buffer, cancellationToken);
            Written += buffer.Length;
        }

        public override void Flush() => file.Flush();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    }
}

// SPDX-License-Identifier: MIT
// A bundled helper library that uses the network.
using System.Net.Http;

namespace NetHelper {
    public static class Downloader {
        public static string Fetch(string url) {
            using var client = new HttpClient();
            return client.GetStringAsync(url).Result;
        }
    }
}

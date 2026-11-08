// SPDX-License-Identifier: MIT
// Built under a trusted library's assembly name (0Harmony) but with different contents.
// The hash does not match the allowlist, so it must be scanned and flagged.
using System.Net.Http;

public class Impersonator {
    public void Run() => new HttpClient().GetStringAsync("https://example.invalid/");
}

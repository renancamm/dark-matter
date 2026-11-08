// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DarkMatter.Cli;

/// <summary>JSON serialization settings and the version stamp shared by every output file.</summary>
internal static class JsonOutput {
    public static readonly JsonSerializerOptions Options = new() {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.KebabCaseLower) },
    };

    public static string ToolVersion { get; } =
        "darkmatter " + (typeof(JsonOutput).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0] ?? "?");

    /// <summary>
    /// The tool, runtime and policy versions a result was produced with. The runtime matters
    /// because its shared framework decides which assemblies count as the framework.
    /// </summary>
    public static object Stamp(Policy policy) => new {
        tool = ToolVersion,
        runtime = Environment.Version.ToString(),
        policy = new { version = policy.Version, sha256 = policy.Sha256 },
    };

    public static void Write(string path, object value) => File.WriteAllText(path, JsonSerializer.Serialize(value, Options));
}

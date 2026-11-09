// SPDX-License-Identifier: MIT
using System.Diagnostics;

namespace DarkMatter.Pipeline.Scan;

/// <summary>
/// Runs the analyzer (<c>darkmatter</c>) as a separate process. The pipeline and the analyzer share
/// no code: the process that reads mod code never loads the pipeline's network or extraction code,
/// and can be run with no network at all.
/// </summary>
internal sealed class AnalyzerProcess(string dll) {
    public string Dll { get; } = File.Exists(dll) ? dll : throw new UsageException($"analyzer not found: {dll} (build src/DarkMatter, or pass --analyzer FILE)");

    /// <summary>The analyzer next to this program (both build into the same folder).</summary>
    public static string DefaultPath => Path.Join(AppContext.BaseDirectory, "darkmatter.dll");

    /// <summary>Runs <c>darkmatter ARGS</c>; returns its exit code, standard output and standard error.</summary>
    public (int Exit, string Out, string Err) Run(IReadOnlyList<string> args) {
        // Run through the same dotnet host as this program when there is one.
        var host = Environment.ProcessPath is { } p && Path.GetFileNameWithoutExtension(p).Equals("dotnet", StringComparison.OrdinalIgnoreCase) ? p : "dotnet";
        var start = new ProcessStartInfo(host) {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        start.ArgumentList.Add(Dll);
        foreach (var a in args) start.ArgumentList.Add(a);
        using var process = Process.Start(start) ?? throw new IOException($"cannot start {host}");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        process.WaitForExit();
        return (process.ExitCode, stdout.Result, stderr.Result);
    }

    /// <summary>Runs the analyzer and throws with its error output when it fails.</summary>
    public string Check(IReadOnlyList<string> args, string what) => Checked(args, what).Out;

    /// <summary>As <see cref="Check"/>, also returning the error output of a run that succeeded (its warnings).</summary>
    public (string Out, string Err) Checked(IReadOnlyList<string> args, string what) {
        var (exit, stdout, stderr) = Run(args);
        if (exit != 0) throw new AnalyzerException($"{what} failed (exit {exit}): {Tail(stderr)}");
        return (stdout, stderr);
    }

    static string Tail(string s) {
        var lines = s.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return string.Join(" / ", lines.TakeLast(3));
    }
}

/// <summary>The analyzer failed; the message holds the end of its error output.</summary>
internal sealed class AnalyzerException(string message) : Exception(message);

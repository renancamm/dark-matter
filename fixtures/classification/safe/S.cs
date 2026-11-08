// SPDX-License-Identifier: MIT
// Everyday framework code: collections, LINQ, formatting, maths, tasks, console output. Every
// member it uses is on the policy's safe list, so it must stay in Known access with no labels.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

public class SafeFramework {
    public static string Summary(IEnumerable<double> values) {
        var list = new List<double>(values);
        var byBucket = list.GroupBy(v => (int)Math.Floor(v)).ToDictionary(g => g.Key, g => g.Count());
        var sb = new StringBuilder();
        foreach (var (bucket, count) in byBucket.OrderBy(kv => kv.Key).Select(kv => (kv.Key, kv.Value)))
            sb.Append($"{bucket}: {count}, ");
        return sb.ToString().TrimEnd(',', ' ') + string.Format(" (max {0:F2})", list.DefaultIfEmpty().Max());
    }

    public static float Length(float x, float y, float z) => new Vector3(x, y, z).Length();

    public static async Task<int> Later(int n) {
        await Task.Delay(1);
        return n * 2;
    }

    public static void Log(string message) => Console.WriteLine($"[{DateTime.UtcNow:O}] {message}");
}

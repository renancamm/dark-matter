// SPDX-License-Identifier: MIT
// Control: a fast getter compiled from an expression tree over a property looked up by a constant
// name. The compiled code calls only that getter. Expected: Known access.
using System;
using System.Linq.Expressions;

public class Settings {
    public int Volume { get; set; } = 3;
}

public static class FastGetter {
    public static Func<Settings, int> Volume() {
        var settings = Expression.Parameter(typeof(Settings), "settings");
        var body = Expression.Property(settings, typeof(Settings).GetProperty("Volume")!);
        return Expression.Lambda<Func<Settings, int>>(body, settings).Compile();
    }
}

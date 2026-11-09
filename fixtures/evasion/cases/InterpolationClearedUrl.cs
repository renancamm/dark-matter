// SPDX-License-Identifier: MIT
// Probe case: as InterpolationCleared, with a web address as the second text, loaded as XML.
// Expected: "Connects to the internet" (G1a review A12).
using System.IO;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

public static class InterpolationClearedUrl {
    static string Own => Path.GetDirectoryName(typeof(InterpolationClearedUrl).Assembly.Location);

    public static XDocument Load() {
        var h = new DefaultInterpolatedStringHandler(0, 1);
        h.AppendFormatted(Own);
        h.ToStringAndClear();
        h.AppendLiteral("https://example.invalid/feed.xml");
        return XDocument.Load(h.ToStringAndClear());
    }
}

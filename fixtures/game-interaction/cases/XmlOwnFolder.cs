// SPDX-License-Identifier: MIT
// Control: an XML document loaded from a path that begins with the mod's own folder, with a name
// the check cannot trace appended (it comes from the game, through a public method). It is a file,
// not a web address. Expected: Known access, "Reads files outside the game" (the untraced part) and
// no "Connects to the internet".
using System.IO;
using System.Xml.Linq;

public static class PartCatalog {
    static string Root => Path.GetDirectoryName(typeof(PartCatalog).Assembly.Location)!;

    public static XDocument Read(string name) => XDocument.Load(Path.Combine(Root, name));
}

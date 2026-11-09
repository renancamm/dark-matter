// SPDX-License-Identifier: MIT
// Control, shaped like CompactHUD's window settings: a folder under the mod's own folder is created,
// an XML document is saved into it, and loaded back from an interpolated path in the same folder
// (an XML load is a web request only when its path is untraced or a web address).
// Expected: Limited access, "Changes files in its own or the game's folders" only.
using System.IO;
using System.Reflection;
using System.Xml.Linq;

public static class OwnFolderXml {
    static string Folder => Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!, "Config");

    public static void SaveWinPos(float x, float y) {
        Directory.CreateDirectory(Folder);
        new XDocument(new XElement("Window", new XAttribute("X", x), new XAttribute("Y", y))).Save(Path.Combine(Folder, "WindowPositions.xml"));
    }

    public static float LoadX() {
        var path = $"{Folder}/WindowPositions.xml";
        return File.Exists(path) ? (float)XDocument.Load(path).Root!.Attribute("X")! : 0f;
    }
}

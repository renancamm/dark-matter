// SPDX-License-Identifier: MIT
// Control: settings read with XmlSerializer for a generic type parameter, which the caller chooses.
// Since policy 15 this is told apart from a type the code names ("xml-serialization-open"), since
// the game's own helpers of this shape pass it on to mods that choose the type. Expected: Broad
// access, deep game access, that reason only.
using System.IO;
using System.Xml.Serialization;

public static class SettingsFile<T> where T : new() {
    public static T Load(string path) {
        using var reader = new StreamReader(path);
        return (T?)new XmlSerializer(typeof(T)).Deserialize(reader) ?? new T();
    }
}

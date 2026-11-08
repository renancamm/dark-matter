// SPDX-License-Identifier: MIT
// The rule next to XmlOwnFolder: an XML load from a path the check cannot trace at all can be a web
// address. Expected: Known access, "Connects to the internet".
using System.Xml.Linq;

public static class RemoteCatalog {
    public static XDocument Read(string location) => XDocument.Load(location);
}

// SPDX-License-Identifier: MIT
// H9 (policy 29): XmlSerializer(Type, XmlAttributeOverrides) can be given more types through the overrides
// (XmlArrayItemAttribute(string, Type)), which the check does not follow: "xml-serialization-open". The
// unknown-node callbacks are safe. Before H9: unclassified.
using System.IO;
using System.Xml;
using System.Xml.Serialization;

public class XmlOverridesTemplate { public string[] Items = []; }

public static class XmlOverrides {
    public static object? Read(string xml) {
        var attrs = new XmlAttributes();
        attrs.XmlArrayItems.Add(new XmlArrayItemAttribute("item", typeof(string)));
        var overrides = new XmlAttributeOverrides();
        overrides.Add(typeof(XmlOverridesTemplate), "Items", attrs);
        var serializer = new XmlSerializer(typeof(XmlOverridesTemplate), overrides);
        var events = new XmlDeserializationEvents {
            OnUnknownAttribute = (_, e) => System.Console.WriteLine(e.Attr.Name),
            OnUnknownElement = (_, e) => System.Console.WriteLine(e.Element.Name),
        };
        using var reader = XmlReader.Create(new StringReader(xml));
        return serializer.Deserialize(reader, events);
    }
}

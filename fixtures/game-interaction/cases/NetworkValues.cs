// SPDX-License-Identifier: MIT
// Control: IP addresses and endpoints as values, and the computer's own network interfaces, without
// connecting anywhere. Expected: Limited access, "Reads information about you and your computer" (the
// interfaces) and no "Connects to the internet".
using System.Net;
using System.Net.NetworkInformation;

public static class AddressInfo {
    public static string Describe(string text) {
        var address = IPAddress.Parse(text);
        var endpoint = new IPEndPoint(address, 7777);
        return endpoint.Address.ToString() + ":" + endpoint.Port + " of " + NetworkInterface.GetAllNetworkInterfaces().Length;
    }
}

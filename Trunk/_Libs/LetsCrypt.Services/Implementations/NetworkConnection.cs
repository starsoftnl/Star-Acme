using System.Net;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace LetsCrypt.Services;

internal class NetworkConnection : IDisposable
{
    #region PInvoke

    private enum ResourceScope : int
    {
        Connected = 1,
        GlobalNetwork,
        Remembered,
        Recent,
        Context
    };

    private enum ResourceType : int
    {
        Any = 0,
        Disk = 1,
        Print = 2,
        Reserved = 8,
    }

    private enum ResourceDisplaytype : int
    {
        Generic = 0x0,
        Domain = 0x01,
        Server = 0x02,
        Share = 0x03,
        File = 0x04,
        Group = 0x05,
        Network = 0x06,
        Root = 0x07,
        Shareadmin = 0x08,
        Directory = 0x09,
        Tree = 0x0a,
        Ndscontainer = 0x0b
    }


    [StructLayout(LayoutKind.Sequential)]
    private class NetResource
    {
        public ResourceScope Scope;
        public ResourceType ResourceType;
        public ResourceDisplaytype DisplayType;
        public int Usage;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? LocalName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? RemoteName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? Comment;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? Provider;
    }

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetAddConnection2W")]
    private static extern int WNetAddConnection2( NetResource netResource, string? password, string? username, int flags );

    [DllImport("mpr.dll", CharSet = CharSet.Unicode, EntryPoint = "WNetCancelConnection2W")]
    private static extern int WNetCancelConnection2( string name, int flags, bool force );

    #endregion

    private string NetworkName;

    public NetworkConnection(string networkName, NetworkCredential credentials)
    {
        NetworkName = networkName;

        var netResource = new NetResource()
        {
            Scope = ResourceScope.GlobalNetwork,
            ResourceType = ResourceType.Disk,
            DisplayType = ResourceDisplaytype.Share,
            RemoteName = networkName
        };

        var userName = string.IsNullOrEmpty(credentials.Domain)
            ? credentials.UserName
            : string.Format(@"{0}\{1}", credentials.Domain, credentials.UserName);

        var result = WNetAddConnection2(
            netResource,
            credentials.Password,
            userName,
            0);

        if (result != 0)
            throw new Win32Exception(result);
    }

    ~NetworkConnection()
    {
        Dispose(false);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        WNetCancelConnection2(NetworkName, 0, true);
    }
}
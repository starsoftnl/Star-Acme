using LetsCrypt.Services;
using MailKit;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1.X509;
using System.Net;
using System.Reactive.Disposables;
using System.Threading;

namespace LetsCrypt.Services;

internal class Authentications : IDisposable
{
    private List<NetworkConnection> Connections = new();

    public static Authentications Create(CertificateTargetAuthentication[] authentications)
    {
        var result = new Authentications();

        try
        {

            foreach (var authentication in authentications)
                result.Connections.Add(Connect(authentication));

            return result;
        }
        catch (Exception)
        {
            result.Dispose();
            throw;
        }
    }

    private static NetworkConnection Connect(CertificateTargetAuthentication authentication)
    {
        var credentials = new NetworkCredential(authentication.Username, authentication.Password, authentication.Domain);
        return new NetworkConnection(authentication.NetworkShare, credentials);
    }

    public void Dispose()
    {
        foreach (var connection in Connections)
            connection.Dispose();
    }
}

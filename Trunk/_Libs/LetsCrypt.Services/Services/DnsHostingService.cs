using Microsoft.Extensions.Logging;
using System.Text;

namespace LetsCrypt.Services;

[Transient(typeof(IDnsHostingService))]
internal class DnsHostingService : IDnsHostingService
{
    private readonly ILogger<DnsHostingService> Logger;
    private readonly IEnumerable<IDnsHostingClient> DnsHostingClients;

    public DnsHostingService(
        ILogger<DnsHostingService> logger, 
        IEnumerable<IDnsHostingClient> dnsHostingClients)
    {
        Logger = logger;
        DnsHostingClients = dnsHostingClients;
    }

    private IDnsHostingClient GetClient( string provider )
    {
        var client = DnsHostingClients.FirstOrDefault(c => c.ProviderName.IsLike(provider));

        if (client == null)
        {
            var message = new StringBuilder($"There is no DNS provider with name {provider}");
            message.AppendLine();
            message.AppendLine("Available providers are:");
            foreach (var c in DnsHostingClients)
                message.AppendLine(c.ProviderName);

            message.AppendLine();

            throw new NullReferenceException(message.ToString());
        }

        return client;
    }

    public async Task DeleteRecordAsync(string provider, string zone, string name, string type, CancellationToken cancellationToken)
        => await GetClient(provider).DeleteRecordAsync(zone, name, type, cancellationToken);

    public async Task SetRecordAsync(string provider, string zone, string name, string type, DnsValue[] values, CancellationToken cancellationToken)
        => await GetClient(provider).SetRecordAsync( zone, name, type, values, cancellationToken);    
}


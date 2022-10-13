namespace LetsCrypt.Services;

internal interface IDnsHostingClient
{
    string ProviderName { get; }

    Task SetRecordAsync(string zone, string name, string type, DnsValue[] values, CancellationToken cancellationToken);

    Task DeleteRecordAsync(string zone, string name, string type, CancellationToken cancellationToken);
}

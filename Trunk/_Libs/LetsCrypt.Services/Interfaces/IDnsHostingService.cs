namespace LetsCrypt.Services;

internal interface IDnsHostingService
{
    Task SetRecordAsync(string provider, string zone, string name, string type, DnsValue[] values, CancellationToken cancellationToken);

    Task DeleteRecordAsync(string provider, string zone, string name, string type, CancellationToken cancellationToken);
}

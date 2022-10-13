namespace LetsCrypt.Services.Models;

internal class DnsRecords : Dictionary<string, DnsEntry>
{
    public DnsRecords()
        : base(StringComparer.InvariantCultureIgnoreCase)
    {
    }
}


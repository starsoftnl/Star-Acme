namespace LetsCrypt.Services.Models;

internal class DnsValue
{
    public int? id { get; set; }

    public string? content { get; set; }

    public int? ttl { get; set; }

    public string[]? flags { get; set; }
}

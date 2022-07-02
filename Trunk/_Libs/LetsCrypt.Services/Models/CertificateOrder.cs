namespace LetsCrypt.Services.Models;

internal class CertificateOrder
{
    public string Id { get; set; } = default!;
    public string[] DnsNames { get; set; } = Array.Empty<string>();
    public string? PfxPassword { get; set; }
    public KeyAlgorithms KeyAlgorithm { get; set; } = KeyAlgorithms.Rsa;
    public int KeySize { get; set; } = 2048;
}

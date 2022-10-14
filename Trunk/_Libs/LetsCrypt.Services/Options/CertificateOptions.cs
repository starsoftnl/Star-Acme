namespace LetsCrypt.Services.Options;

internal class CertificateOptions
{
    public string[] DnsNames { get; set; } = Array.Empty<string>();
    public string? PfxPassword { get; set; }
    public KeyAlgorithms KeyAlgorithm { get; set; } = KeyAlgorithms.Rsa;
    public int KeySize { get; set; } = 2048;
    public double RenewalFactor { get; set; } = 0.3;

    public string DnsHostingProvider { get; set; } = "nederhost.nl";
    public string DnsHostingZone { get; set; } = default!;
    public bool DnsUpdateValidation { get; set; } = false;
    public TimeSpan DnsUpdateDelay { get; set; } = TimeSpan.FromSeconds(120);
}

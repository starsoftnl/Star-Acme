namespace LetsCrypt.Services.Models;

internal class CertificateTargetIIS : CertificateTargetBase
{
    public string Website { get; set; } = "Default Web Site";
    public string[] Bindings { get; set; } = Array.Empty<string>();
}

namespace LetsCrypt.Services.Models;

internal class CertificateTargetHttpSys : CertificateTargetBase
{
    public string[] Bindings { get; set; } = Array.Empty<string>();
}

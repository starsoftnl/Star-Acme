using System.Net;
using System.Security.Cryptography;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceHomeAssistant : DeploymentServiceBase
{
    public DeploymentServiceHomeAssistant(
        ILogger<DeploymentServiceHomeAssistant> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.HomeAssistant?.Phase ?? 0;
        max = Target.HomeAssistant?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.HomeAssistant?.Enabled != true || Target.HomeAssistant.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.HomeAssistant, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetHomeAssistant ha, CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return;

        var certificate = new X509Certificate2(pfx, PfxPassword, X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

        var privateKeyPem = GetPrivateKeyPem(certificate);
        var certificatePem = GetCertificatePem(certificate);

        var unc = $"\\\\{ComputerName}{ha.SharedFolder}";
        using var connection = new NetworkConnection(unc, new NetworkCredential(ha.Username, ha.Password));

        await File.WriteAllTextAsync($"\\\\{ComputerName}{ha.PrivateKeyPath}", privateKeyPem, cancellationToken);
        await File.WriteAllTextAsync($"\\\\{ComputerName}{ha.FullChainPath}", certificatePem, cancellationToken);
    }

    private string GetPrivateKeyPem(X509Certificate2 certificate)
    {
        if (certificate.GetRSAPrivateKey() is RSA rsaKey)
            return new string(PemEncoding.Write("PRIVATE KEY", rsaKey.ExportPkcs8PrivateKey()));
        
        if (certificate.GetECDsaPrivateKey() is ECDsa ecdsaKey)
            return new string(PemEncoding.Write("PRIVATE KEY", ecdsaKey.ExportPkcs8PrivateKey()));

        if (certificate.GetDSAPrivateKey() is DSA dsaKey)
            return new string(PemEncoding.Write("PRIVATE KEY", dsaKey.ExportPkcs8PrivateKey()));

        throw new CryptographicException("Unknown certificate algorithm");
    }

    private string GetCertificatePem(X509Certificate2 certificate)
    {
        return new string(PemEncoding.Write("CERTIFICATE", certificate.RawData));
    }
}

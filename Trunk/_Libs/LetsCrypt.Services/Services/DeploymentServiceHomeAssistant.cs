using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceHomeAssistant : DeploymentServiceBase
{
    public DeploymentServiceHomeAssistant(
        ILogger<DeploymentServiceHomeAssistant> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.HomeAssistant?.Enabled == true)
            await DeployCertificateAsync(Target.HomeAssistant, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetHomeAssistant ha, CancellationToken cancellationToken)
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

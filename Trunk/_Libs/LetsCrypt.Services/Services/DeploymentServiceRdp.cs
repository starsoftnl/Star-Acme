using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceRdp : DeploymentServiceBase
{
    public DeploymentServiceRdp(
        ILogger<DeploymentServiceRdp> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificateOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override int? GetPhaseCount()
        => Target.Rdp?.Phase;

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        var rdp = Target.Rdp;
        if(rdp?.Enabled == true && rdp.Phase == Phase)
            await DeployCertificateAsync(rdp, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetRdp rdp, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", rdp.StoreName);
        LoggerContext.Set("Method", "Rdp");

        await ImportCertificateAsync(rdp.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        await AddAccessRightsToCertificateAsync( rdp.StoreName, thumbprint, "NETWORK SERVICE", cancellationToken);

        await SetRegistryKeyAsync("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "SSLCertificateSHA1Hash", thumbprint);

        await RestartServiceAsync("Remote Desktop Services", cancellationToken);
    }
}

using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceRdp : DeploymentServiceBase
{
    public DeploymentServiceRdp(
        ILogger<DeploymentServiceRdp> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Rdp?.Phase ?? 0;
        max = Target.Rdp?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Rdp?.Enabled != true || Target.Rdp.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Rdp, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetRdp rdp, CancellationToken cancellationToken)
    {
        if( !await CopyCertificateAsync(cancellationToken) ) return;

        LoggerContext.Set("StoreName", rdp.StoreName);
        LoggerContext.Set("Method", "Rdp");

        await ImportCertificateAsync(rdp.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        Logger.Information("Bind certificate");

        await AddAccessRightsToCertificateAsync( 
            rdp.StoreName, 
            thumbprint, 
            "NETWORK SERVICE", 
            cancellationToken);

        await SetRegistryKeyAsync(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", 
            "SSLCertificateSHA1Hash", 
            thumbprint, 
            cancellationToken);

        await RestartServiceAsync(
            "Remote Desktop Services", 
            cancellationToken);
    }
}

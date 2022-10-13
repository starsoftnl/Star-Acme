using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWindowsService : DeploymentServiceBase
{
    public DeploymentServiceWindowsService(
        ILogger<DeploymentServiceWindowsService> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        foreach (var ws in Target.WindowsServices)
            if (ws?.Enabled == true)
                await DeployCertificateAsync(ws, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetWindowsService ws, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", ws.StoreName);
        LoggerContext.Set("Method", "Windows Service");
        LoggerContext.Set("Display Name", ws.ServiceDisplayName);

        await ImportCertificateAsync(ws.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Restart Service");

        await RestartServiceAsync(ws.ServiceDisplayName, cancellationToken);
    }
}

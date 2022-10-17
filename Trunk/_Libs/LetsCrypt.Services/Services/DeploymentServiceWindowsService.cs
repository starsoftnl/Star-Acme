using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWindowsService : DeploymentServiceBase
{
    public DeploymentServiceWindowsService(
        ILogger<DeploymentServiceWindowsService> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        if (Target.WindowsServices != null && Target.WindowsServices.Length > 0)
        {
            min = Target.WindowsServices.Min(h => h.Phase);
            max = Target.WindowsServices.Max(h => h.Phase);
        }
        else max = min = 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset? next = null;

        foreach (var service in Target.WindowsServices)
            if (service?.Enabled == true && service.Phase == Phase)
            {
                next ??= await UpdateCertificateAsync(cancellationToken);
                await DeployCertificateAsync(service, cancellationToken);
            }

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetWindowsService ws, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken)) return;

        LoggerContext.Set("StoreName", ws.StoreName);
        LoggerContext.Set("Method", "Windows Service");
        LoggerContext.Set("Display Name", ws.ServiceDisplayName);

        await ImportCertificateAsync(ws.StoreName, cancellationToken);

        Logger.Information("Restart Service");

        await RestartServiceAsync(ws.ServiceDisplayName, cancellationToken);
    }
}

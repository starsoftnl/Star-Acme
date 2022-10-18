using System.Net;
using System.Reactive;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWac : DeploymentServiceBase
{
    public DeploymentServiceWac(
        ILogger<DeploymentServiceWac> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Wac?.Phase ?? 0;
        max = Target.Wac?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Wac?.Enabled != true || Target.Wac.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Wac, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetWac wac, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken)) return;

        LoggerContext.Set("StoreName", wac.StoreName);
        LoggerContext.Set("Method", "WAC");

        await ImportCertificateAsync(wac.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        Logger.Information("Bind certificate");

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"netsh http delete sslcert ipport=0.0.0.0:{wac.Port}");
        script.AppendLine($"netsh http delete urlacl url=https://+:{wac.Port}/");
        script.AppendLine($"netsh http add urlacl url=https://+:{wac.Port}/ user='NT Authority\\Network Service'");
        script.AppendLine($"netsh http add sslcert ipport=0.0.0.0:{wac.Port} certhash='{thumbprint}' appid='{{9A81E8DC-5AFD-46B6-A728-93218D11C0B9}}'");
        await RunRemoteScriptAsync(script.ToString(), cancellationToken);

        await RestartServiceAsync("Windows Admin Center Service", cancellationToken);
    }
}

using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceUnifi : DeploymentServiceBase
{
    public DeploymentServiceUnifi(
        ILogger<DeploymentServiceUnifi> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Unifi?.Phase ?? 0;
        max = Target.Unifi?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Unifi?.Enabled != true || Target.Unifi.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Unifi, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetUnifi unifi, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        await ImportCertificateAsync(unifi.StoreName, cancellationToken);

        await ExportCertificateAsync(unifi.StoreName, "aircontrolenterprise", true, cancellationToken);

        LoggerContext.Set("StoreName", unifi.StoreName);
        LoggerContext.Set("Method", "Unifi");

        var filePathLocal = GetLocalCertificatePath();
        var alias = DnsNames.First();

        LoggerContext.Set("Alias", alias);
        Logger.Information("Bind certificate");

        var keystore = Path.Combine(unifi.UnifiPath, "data", "keystore");

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"Set-Location -Path '{unifi.UnifiPath}'");
        script.AppendLine($"java -jar lib\\ace.jar stopsvc");
        await RunRemoteScriptAsync(script.ToString(), cancellationToken);

        await TryRunRemoteScriptAsync($"&'{unifi.KeyToolPath}' -delete -keystore '{keystore}' -alias 'unifi' -srcstorepass 'aircontrolenterprise' -deststorepass aircontrolenterprise -noprompt\r\n", cancellationToken);
        await TryRunRemoteScriptAsync($"&'{unifi.KeyToolPath}' -changealias -keystore '{keystore}' -alias '{alias}' -destalias unifi -srcstorepass 'aircontrolenterprise' -deststorepass aircontrolenterprise -noprompt", cancellationToken);
        await RunRemoteScriptAsync($"java -jar lib\\ace.jar startsvc", cancellationToken);



    }
}

using System.Net;
using System.Security.Cryptography.X509Certificates;

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

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-Location")
                .AddArgument(unifi.UnifiPath));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript("java -jar lib\\ace.jar stopsvc"));

            var keystore = Path.Combine(unifi.UnifiPath, "data", "keystore");

            result = await remote.SafeExecuteAsync(shell => shell
                .AddScript($"&'{unifi.KeyToolPath}' -delete -keystore '{keystore}' -alias 'unifi' -srcstorepass 'aircontrolenterprise' -deststorepass aircontrolenterprise -noprompt"));

            result = await remote.SafeExecuteAsync(shell => shell
                .AddScript($"&'{unifi.KeyToolPath}' -importkeystore -srckeystore '{filePathLocal}' -srcstoretype pkcs12 -srcstorepass 'aircontrolenterprise' -destkeystore '{keystore}' -deststorepass aircontrolenterprise -noprompt"));

            result = await remote.SafeExecuteAsync(shell => shell
                .AddScript($"&'{unifi.KeyToolPath}' -changealias -keystore '{keystore}' -alias '{alias}' -destalias unifi -srcstorepass 'aircontrolenterprise' -deststorepass aircontrolenterprise -noprompt"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript("java -jar lib\\ace.jar startsvc"));
        });
    }
}

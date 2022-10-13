using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceUnifi : DeploymentServiceBase
{
    public DeploymentServiceUnifi(
        ILogger<DeploymentServiceUnifi> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Unifi?.Enabled == true)
            await DeployCertificateAsync(Target.Unifi, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetUnifi unifi, CancellationToken cancellationToken)
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

using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWac : DeploymentServiceBase
{
    public DeploymentServiceWac(
        ILogger<DeploymentServiceWac> logger, 
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Wac?.Enabled == true)
            await DeployCertificateAsync(Target.Wac, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetWac wac, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", wac.StoreName);
        LoggerContext.Set("Method", "WAC");

        await ImportCertificateAsync(wac.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Stop-Service")
                .AddArgument("ServerManagementGateway"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http delete sslcert ipport=0.0.0.0:{wac.Port}"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http delete urlacl url=https://+:{wac.Port}/"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http add urlacl url=https://+:{wac.Port}/ user='NT Authority\\Network Service'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http add sslcert ipport=0.0.0.0:{wac.Port} certhash='{thumbprint}' appid='{{9A81E8DC-5AFD-46B6-A728-93218D11C0B9}}'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Start-Service")
                .AddArgument("ServerManagementGateway"));


            //result = await remote.ExecuteAsync(shell => shell
            //    .AddScript("$wac = get-wmiobject Win32_Product | select IdentifyingNumber, Name, LocalPackage | Where Name -eq 'Windows Admin Center'"));

            //var items = new List<string>();
            //items.Add($"/i $($wac.LocalPackage)");
            //items.Add($"/qn");
            //items.Add($"/L*v c:\\Admin\\wac-install-log.txt");
            //items.Add($"SME_PORT=443");
            //items.Add($"SME_THUMBPRINT={thumbprint}");
            //items.Add($"SSL_CERTIFICATE_OPTION=installed");
            //var args = string.Join(" ", items);

            //result = await remote.ExecuteAsync(shell => shell
            //    .AddCommand("Start-Process")
            //    .AddArgument("msiexec.exe")
            //    .AddParameter("Wait")
            //    .AddParameter("ArgumentList", args)
            //    );

            //result = await remote.ExecuteAsync(shell => shell
            //    .AddCommand("Start-Service")
            //    .AddArgument("ServerManagementGateway"));
        });
    }
}

using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceIIS : DeploymentServiceBase
{
    public DeploymentServiceIIS(
        ILogger<DeploymentServiceIIS> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        if (Target.IIS != null && Target.IIS.Length > 0)
        {
            min = Target.IIS.Min(h => h.Phase);
            max = Target.IIS.Max(h => h.Phase);
        }
        else max = min = 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset? next = null;

        foreach (var iis in Target.IIS)
            if (iis?.Enabled == true && iis.Phase == Phase)
            {
                next ??= await UpdateCertificateAsync(cancellationToken);
                await DeployCertificateAsync(iis, cancellationToken);
            }

        return next;
    }

    // Requires
    // [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    // Install-Module –Name IISAdministration -RequiredVersion 1.1.0.0
    // Install-Module –Name IISAdministration -Force

    private async Task DeployCertificateAsync(DeploymentTargetIIS iis, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", iis.StoreName);
        LoggerContext.Set("Method", "IIS");
        LoggerContext.Set("Website", iis.Website);

        await ImportCertificateAsync(iis.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Import-Module")
                .AddArgument("WebAdministration"));

            foreach (var binding in iis.Bindings)
            {
                LoggerContext.Set("Binding", binding);
                Logger.Information("Bind certificate");

                result = await remote.ExecuteAsync(shell => shell
                    .AddCommand("Remove-IISSiteBinding")
                    .AddParameter("Name", iis.Website)
                    .AddParameter("BindingInformation", binding.Trim('?'))
                    .AddParameter("Protocol", "https")
                    .AddParameter("Confirm", false));

                result = await remote.ExecuteAsync(shell =>
                {
                    shell.AddCommand("New-IISSiteBinding")
                        .AddParameter("Name", iis.Website)
                        .AddParameter("BindingInformation", binding.Trim('?'))
                        .AddParameter("CertStoreLocation", $"Cert:\\LocalMachine\\{iis.StoreName}")
                        .AddParameter("CertificateThumbPrint", certificate.Thumbprint)
                        .AddParameter("Force")
                        .AddParameter("Protocol", "https");

                    if (binding.Split(":").Length == 3 && !string.IsNullOrEmpty(binding.Split(":")[2]) && !binding.EndsWith("?"))
                        shell.AddParameter("SslFlag", "Sni");
                });

                if( iis.RestartService )
                    await RestartServiceAsync("World Wide Web Publishing Service", cancellationToken);
            }

            // shell.AddScript($"Get-ChildItem -path IIS:\\SSLbindings | Where-Object {{ ($_.Port -eq {iis.Port}) -and ($_.Host -eq \"{iis.Hostname}\") -and ($_.IPAddress -match \"{iis.IpAddress}\") }} | Remove-Item");
            // shell.AddScript($"Add-NetIPHttpsCertBinding -CertificateHash {thumbprint} ");
            // Get-ChildItem -path IIS:\SSLbindings | Where-Object { ($_.Port -like 443) -and ($_.Host -like "mail.starsoft.nl") -and ($_.IPAddress -like "") }
        });

        //var remoteName = $"\\\\{deploy.ComputerName}\\{iis.StoreName}";
        //UpdateCertificateStore(remoteName, StoreLocation.LocalMachine, certificate);


        //var results = await ExecuteNetShellAsync(deploy, "netsh http show sslcert", cancellationToken);

        //if (IPAddress.TryParse(iis.Hostname, out var a))
        //{
        //    var regex = new Regex($"\\s+IP:port\\s+:\\s{iis.Hostname}:{iis.Port}");
        //    if (results.Any(s => regex.IsMatch(s)))
        //    {
        //        results = await ExecuteNetShellAsync(deploy, $"netsh http delete sslcert ipport=\"{iis.Hostname}:{iis.Port}\"", cancellationToken);
        //    }
        //    results = await ExecuteNetShellAsync(deploy, $"netsh http add sslcert ipport=\"{iis.Hostname}:{iis.Port}\" certhash={certificate.Thumbprint} certstorename={iis.StoreName} appid=\"{id}\"", cancellationToken);
        //}
        //else
        //{
        //    var regex = new Regex($"\\s+Hostname:port\\s+:\\s{iis.Hostname}:{iis.Port}");
        //    if (results.Any(s => regex.IsMatch(s)))
        //    {
        //        results = await ExecuteNetShellAsync(deploy, $"netsh http delete sslcert hostnameport=\"{iis.Hostname}:{iis.Port}\"", cancellationToken);
        //    }
        //    results = await ExecuteNetShellAsync(deploy, $"netsh http add sslcert hostnameport=\"{iis.Hostname}:{iis.Port}\" certhash={certificate.Thumbprint} certstorename={iis.StoreName} appid=\"{id}\"", cancellationToken);
        //}
    }

}

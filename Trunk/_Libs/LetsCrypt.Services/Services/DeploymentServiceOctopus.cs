using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceOctopus : DeploymentServiceBase
{
    public DeploymentServiceOctopus(
        ILogger<DeploymentServiceOctopus> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Octopus?.Enabled == true)
            await DeployCertificateAsync(Target.Octopus, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetOctopus octopus, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", octopus.StoreName);
        LoggerContext.Set("Method", "Octopus");

        await ImportCertificateAsync(octopus.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;
        var octopusPath = octopus.OctopusPath ?? @"C:\Program Files\Octopus Deploy\Octopus";

        LoggerContext.Set("IPAddress", octopus.IpAddress);
        LoggerContext.Set("Port", octopus.Port);
        Logger.Information("Bind certificate");

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-Location")
                .AddArgument($"{octopusPath}"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Stop-Service")
                .AddParameter("Name", "OctopusDeploy")
                .AddParameter("Force"));

            var items = new List<string>();
            items.Add($"--thumbprint='{thumbprint}'");
            items.Add($"--certificate-store='{octopus.StoreName}'");

            if (!string.IsNullOrEmpty(octopus.Instance))
                items.Add($"--instance='{octopus.Instance}'");

            if (!string.IsNullOrEmpty(octopus.IpAddress))
                items.Add($"--ip-address='{octopus.IpAddress}'");

            if (octopus.Port != null)
                items.Add($"--port={octopus.Port}");

            result = await remote.ExecuteAsync(shell =>
                shell.AddScript($".\\octopus.server.exe ssl-certificate {string.Join(" ", items)}"));

            //if (!string.IsNullOrEmpty(octopus.LicenseFile))
            //{
            //    LoggerContext.Set("License File", octopus.LicenseFile);
            //    Logger.Information("Update License");

            //    result = await remote.ExecuteAsync(shell =>
            //        shell.AddScript($".\\octopus.server.exe license --licenseFile={octopus.LicenseFile}"));
            //}

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Start-Service")
                .AddParameter("Name", "OctopusDeploy"));
        });
    }
}

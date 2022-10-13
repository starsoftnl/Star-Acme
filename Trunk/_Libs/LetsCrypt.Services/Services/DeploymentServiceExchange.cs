using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceExchange : DeploymentServiceBase
{
    public DeploymentServiceExchange(
        ILogger<DeploymentServiceHttpSys> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        var exchange = Target.Exchange;
        if (exchange?.Enabled == true)
                await DeployCertificateAsync(exchange, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetExchange exchange, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", exchange.StoreName);
        LoggerContext.Set("Method", "Exchange");

        await ImportCertificateAsync(exchange.StoreName, cancellationToken);

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

            //result = await remote.ExecuteAsync(shell => shell
            //    .AddCommand("Add-PSSnapin")
            //    .AddArgument("Microsoft.Exchange.Management.PowerShell.SnapIn"));

            //result = await remote.ExecuteAsync(shell => shell
            //    .AddCommand("Enable-ExchangeCertificate")
            //    .AddParameter("Thumbprint", thumbprint)
            //    .AddParameter("Services", "IIS"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$password = ConvertTo-SecureString '{Password}' -AsPlainText -Force"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$UserCredential = New-Object System.Management.Automation.PSCredential ('{Username}', $password)"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://{ComputerName}.STARSOFT.NL/PowerShell/ -Authentication Kerberos -Credential $UserCredential"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Import-PSSession $Session -DisableNameChecking"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Enable-ExchangeCertificate")
                .AddParameter("Thumbprint", thumbprint)
                .AddParameter("Services", "IIS"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"iisreset"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Remove-PSSession -computername {ComputerName}.STARSOFT.NL"));


            // $password = ConvertTo-SecureString "{}" -AsPlainText -Force
            // $UserCredential = New-Object System.Management.Automation.PSCredential ("STARSOFT\Administrator", $password)
            // $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://EX1.STARSOFT.NL/PowerShell/ -Authentication Kerberos -Credential $UserCredential
            // Import-PSSession $Session -DisableNameChecking
            // iisreset
            // Remove-PSSession -computername EX1.STARSOFT.NL

            // Enable-ExchangeCertificate -Thumbprint F7806AAD453C947BDBBBE1A98100102BAD62CA3F -Services IIS

            // Import-ExchangeCertificate -FileName "<FilePathOrUNCPath>\<FileName>" -Password (ConvertTo-SecureString -String '<Password> ' -AsPlainText -Force) [-PrivateKeyExportable <$true | $false>] [-Server <ServerIdentity>]
            //binding = "0.0.0.0:8172"
            //LoggerContext.Set("Binding", binding);
            //Logger.Information("Bind certificate");

            //    result = await remote.ExecuteAsync(shell =>
            //    {
            //        if (IPAddress.TryParse(binding.Split(":")[0], out var address))
            //            shell.AddScript($"netsh http delete sslcert ipport='{binding}'");
            //        else shell.AddScript($"netsh http delete sslcert hostnameport='{binding}'");
            //    });

            //    result = await remote.ExecuteAsync(shell =>
            //    {
            //        if (IPAddress.TryParse(binding.Split(":")[0], out var address))
            //            shell.AddScript($"netsh http add sslcert ipport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{id}'");
            //        else shell.AddScript($"netsh http add sslcert hostnameport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{id}'");
            //    });


            //result = await remote.ExecuteAsync(shell =>
            //{
            //    shell.AddCommand("Add-NetIPHttpsCertBinding")
            //        .AddParameter("IpPort", binding)
            //        .AddParameter("CertificateStoreName", $"Cert:\\LocalMachine\\{http.StoreName}")
            //        .AddParameter("CertificateHash ", certificate.Thumbprint)
            //        .AddParameter("ApplicationId", id);
            //});
            // }
        });
    }
}

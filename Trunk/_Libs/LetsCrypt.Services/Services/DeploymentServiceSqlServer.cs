using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceSqlServer : DeploymentServiceBase
{
    public DeploymentServiceSqlServer(
        ILogger<DeploymentServiceSqlServer> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        var sql = Target.SqlServer;
        if(sql?.Enabled == true )
            await DeployCertificateAsync(sql, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetSqlServer sql, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", sql.StoreName);
        LoggerContext.Set("Method", "SqlServer");

        await ImportCertificateAsync(sql.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        await AddAccessRightsToCertificateAsync( sql.StoreName, thumbprint, "NT Service\\MSSQLSERVER", cancellationToken);
        
        // Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib
        var instance = $"{sql.InstanceName ?? "MSSQLServer"}";
        await SetRegistryKeyAsync($"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL15.{instance}\\{instance}\\SuperSocketNetLib", "Certificate", thumbprint);
    }
}

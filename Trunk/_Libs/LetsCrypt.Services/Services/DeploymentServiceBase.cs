using System.Net;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Runtime.ConstrainedExecution;
using System.IO;

namespace LetsCrypt.Services.Services;

[Singleton(typeof(IDeploymentService))]
internal abstract class DeploymentServiceBase : IDeploymentService
{
    protected readonly ILogger Logger;
    protected readonly ILetsCryptMailService MailService;
    protected readonly IOptionsMonitor<DeployOptions> DeployOptions;
    protected readonly CertificateService CertificateService;

    public DeploymentServiceBase( 
        ILogger logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
    {
        Logger = logger;
        MailService = mailService;
        DeployOptions = deployOptions;
        CertificateService = certificateService;
    }

    public async Task DeployCertificateAsync(CertificateOrder order, CancellationToken cancellationToken)
    {
        Order = order;
        OrderId = order.Id;
        DnsNames = order.DnsNames;
        PfxPassword = order.PfxPassword;

        foreach (var deploy in DeployOptions.CurrentValue)
        {
            Deploy = deploy;

            foreach( var target in deploy.Targets )
            {
                var certificate = target.Certificate ?? deploy.Certificate;

                if (!certificate.IsLike(OrderId)) 
                    continue;

                if (deploy.ExcludeTargets.Any(t => target.ComputerName.PatternMatch(t, true)))
                    continue;

                if (deploy.IncludeTargets.Length > 0 && !deploy.IncludeTargets.Any(t => target.ComputerName.PatternMatch(t, true)))
                    continue;
                
                Target = target;
                ComputerName = target.ComputerName;                
                Username = target.Username ?? deploy.Username;
                Password = target.Password ?? deploy.Password;
                UncPath = (target.UncPath ?? deploy.UncPath ?? "\\\\{ComputerName}\\C$\\admin\\Certificate").Replace("{ComputerName}", ComputerName);
                LocalPath = (target.LocalPath ?? deploy.LocalPath ?? "c:\\admin\\Certificate").Replace("{ComputerName}", ComputerName);

                LoggerContext.Set("ComputerName", ComputerName);

                IDisposable[] authentications = null!;

                try
                {
                    authentications = target.Authentications.Select(a => Connect(a)).ToArray();

                    await DeployCertificateAsync(cancellationToken);
                }
                catch( Exception ex )
                {
                    var message = $"Deployment of certificate {certificate} failed for target {target.ComputerName}";

                    Logger.Error(ex, message);

                    await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);
                }
                finally
                {
                    if(authentications != null )
                        foreach (var authentication in authentications)
                        {
                            try
                            {
                                authentication.Dispose();
                            }
                            catch( Exception ex )
                            {
                                Logger.Warning(ex, "Failed to dispose network connection");
                            }
                        }
                        
                }
            }
        }
    }

    protected abstract Task DeployCertificateAsync(CancellationToken cancellationToken);

    protected string ApplicationId { get; set; } = new Guid("{A5B777E5-17EE-443C-AA77-E3B7BF6F2295}").ToString("B");
    protected CertificateOrder Order { get; set; } = default!;
    protected CertificateDeploy Deploy { get; set; } = default!;
    protected CertificateTarget Target { get; set; } = default!;

    protected string OrderId { get; set; } = default!;
    protected string[] DnsNames { get; set; } = Array.Empty<string>();
    protected string? PfxPassword { get; set; }
    protected string ComputerName { get; set; } = default!;
    protected string? Username { get; set; }
    protected string? Password { get; set; }
    protected string? UncPath { get; set; }
    protected string? LocalPath { get; set; }

    protected string GetLocalCertificatePath()
        => Path.Join(LocalPath, $"{OrderId}.pfx");

    protected string GetNetworkCertificatePath()
        => Path.Join(UncPath, $"{OrderId}.pfx");

    private NetworkConnection Connect( CertificateTargetAuthentication authentication )
    {
        var credentials = new NetworkCredential(authentication.Username, authentication.Password, authentication.Domain);
        return new NetworkConnection(authentication.NetworkShare, credentials);
    }

    protected async Task<byte[]?> CopyCertificateAsync(CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return null;

        var filePathUnc = GetNetworkCertificatePath();
        var directoryUnc = Path.GetDirectoryName(filePathUnc);

        if (directoryUnc != null && !Directory.Exists(directoryUnc))
            Directory.CreateDirectory(directoryUnc);

        await File.WriteAllBytesAsync(filePathUnc, pfx, cancellationToken);

        return pfx;
    }

    protected async Task SetRegistryKeyAsync( string path, string name, string value )
    {
        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$path = 'Registry::{path}'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$name = '{name}'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$value = '{value}'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"If( -not (Test-Path $path) ) {{ New-Item -Path $path -Force | Out-Null }}"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"New-ItemProperty -Path $path -Name $name -Value $value -Force"));
        });
    }

    protected async Task AddAccessRightsToCertificateAsync( string storeName, string thumbprint, string username, CancellationToken cancellationToken )
    {       
        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript(
                    $"$certs = Get-ChildItem 'Cert:\\LocalMachine\\{storeName}' | " +
                    $"Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }} | " +
                    $"Select-Object -first 1"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certs[0])"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$rule = New-Object System.Security.AccessControl.FileSystemAccessRule '{username}', Read, Allow"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$filepath = [io.path]::combine($env:ALLUSERSPROFILE, 'Microsoft\\Crypto\\Keys', $key.key.UniqueName)"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$acl = Get-Acl -path $filepath"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$acl.AddAccessRule($rule)"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Set-Acl $filepath $acl"));
        });
    }

    protected async Task ChangePasswordCertificateAsync(string password, CancellationToken cancellationToken)
    {
        var filePathLocal = GetLocalCertificatePath();
        var filePathTemp = Path.Combine(Path.GetDirectoryName(filePathLocal)!, "temp.pfx");

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$newpassword = ConvertTo-SecureString -String '{password}' -Force -AsPlainText"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$oldpassword = ConvertTo-SecureString -String '{PfxPassword}' -Force -AsPlainText"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$pfx = Get-PfxData -FilePath '{filePathLocal}' -Password $oldpassword"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Export-PfxCertificate -PFXData $pfx -FilePath {filePathTemp} -Password $newpassword"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Remove-Item")
                .AddParameter("Path", filePathLocal)
                .AddParameter("Force"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Rename-Item")
                .AddParameter("Path", filePathTemp)
                .AddParameter("NewName", filePathLocal)
                .AddParameter("Force"));
        });
    }

    protected async Task ImportCertificateAsync(string storeName, CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return;

        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        var filePathLocal = GetLocalCertificatePath();

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Get-ChildItem 'cert:\\LocalMachine\\{storeName}' | Where-Object {{ $_.Subject -eq 'CN={DnsNames.First()}' -and $_.Thumbprint -ne '{thumbprint}' }} | Remove-Item"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Get-ChildItem 'cert:\\LocalMachine\\{storeName}' | Where-Object {{ $_.Subject -eq 'CN={DnsNames.First()}' -and $_.Thumbprint -eq '{thumbprint}' }}"));

            if (!result.Any(r => r.Contains(thumbprint)))
            {
                Logger.Information("Import certificate into remote store");

                result = await remote.ExecuteAsync(shell => shell
                    .AddScript($"$certImportPwd = ConvertTo-SecureString -String '{PfxPassword}' -AsPlainText -Force"));

                result = await remote.ExecuteAsync(shell => shell
                    .AddScript($"Import-PfxCertificate -FilePath \"{filePathLocal}\" -CertStoreLocation \"cert:\\LocalMachine\\{storeName}\" -Password $certImportPwd -Exportable"));
            }
        });
    }

    protected async Task ExportCertificateAsync(string storeName, string password, bool chain, CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return;

        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        var filePathLocal = GetLocalCertificatePath();
        var chainOption = chain ? "BuildChain" : "EndEntityCertOnly";

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$newpassword = ConvertTo-SecureString -String '{password}' -Force -AsPlainText"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"$oldpassword = ConvertTo-SecureString -String '{PfxPassword}' -Force -AsPlainText"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Export-PfxCertificate -Cert 'cert:\\localmachine\\{storeName}\\{thumbprint}' -FilePath {filePathLocal} -Password $newpassword -ChainOption {chainOption} -Force"));
        });
    }


    protected async Task RemoteAsync(Func<Runspace, Task> tasks)
    {
        var connectionInfo = new WSManConnectionInfo();
        connectionInfo.ComputerName = ComputerName;
        connectionInfo.Credential = new PSCredential(Username, new NetworkCredential("", Password).SecurePassword);

        using var runspace = RunspaceFactory.CreateRunspace(connectionInfo);
        runspace.Open();

        try
        {
            await tasks(runspace);
        }
        finally
        {
            runspace.Close();
        }
    }

    protected void UpdateCertificateStore(string name, StoreLocation location, X509Certificate2 certificate)
    {
        using var store = new X509Store(name, location, OpenFlags.ReadWrite);

        var existing = store.Certificates.Where(c => c.Subject == certificate.Subject).ToList();

        foreach (var remove in existing.Where(e => e.Thumbprint != certificate.Thumbprint || e.NotAfter != certificate.NotAfter))
            store.Remove(remove);

        if (!existing.Any(e => e.Thumbprint == certificate.Thumbprint && e.NotAfter == certificate.NotAfter))
            store.Add(certificate);

        store.Close();
    }

    protected async Task RestartServiceAsync(string displayName, CancellationToken cancellationToken)
    {
        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Restart-Service")
                .AddParameter("Force")
                .AddParameter("DisplayName", displayName));
        });
    }
}

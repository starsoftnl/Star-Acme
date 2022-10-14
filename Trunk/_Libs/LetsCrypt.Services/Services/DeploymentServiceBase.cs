namespace LetsCrypt.Services.Services;

[Singleton(typeof(IDeploymentService))]
internal abstract class DeploymentServiceBase : IDeploymentService
{
    protected readonly ILogger Logger;
    protected readonly ILetsCryptMailService MailService;
    protected readonly IOptionsMonitor<CertificatesOptions> CertificateOptions;
    protected readonly CertificateService CertificateService;

    public DeploymentServiceBase( 
        ILogger logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
    {
        Logger = logger;
        MailService = mailService;
        CertificateOptions = certificateOptions;
        CertificateService = certificateService;
    }

    public void GetPhaseCount(DeploymentTarget target, out int min, out int max)
    {
        Target = target;

        GetPhaseCount(out min, out max);
    }

    public async Task<DateTimeOffset?> RunAsync(DateTimeOffset now, DeploymentOptions deployment, string computerName, DeploymentTarget target, int phase, CancellationToken cancellationToken)
    {
        Now = now;
        Deploy = deployment;
        Target = target;
        Phase = phase;

        ComputerName = computerName;
        Username = Target.Username ?? Deploy.Username;
        Password = Target.Password ?? Deploy.Password;
        UncPath = (Target.UncPath ?? Deploy.UncPath ?? "\\\\{ComputerName}\\C$\\admin\\Certificate").Replace("{ComputerName}", ComputerName);
        LocalPath = (Target.LocalPath ?? Deploy.LocalPath ?? "c:\\admin\\Certificate").Replace("{ComputerName}", ComputerName);

        OrderId = Target.Certificate ?? deployment.Certificate;
        Order = !string.IsNullOrEmpty(OrderId) && CertificateOptions.CurrentValue.TryGetValue(OrderId, out var order) ? order :
            throw new Exception($"No certificate with name {OrderId}");

        DnsNames = Order.DnsNames;
        PfxPassword = Order.PfxPassword;

        if (Deploy.ExcludeTargets.Any(t => computerName.PatternMatch(t, true))) return null;            
        if (Deploy.IncludeTargets.Length > 0 && !Deploy.IncludeTargets.Any(t => computerName.PatternMatch(t, true))) return null;

        using var authentications = Authentications.Create(Target.Authentications);

        return await DeployCertificateAsync(cancellationToken);
    }

    protected abstract void GetPhaseCount(out int min, out int max);

    protected abstract Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken);

    protected string ApplicationId { get; set; } = new Guid("{A5B777E5-17EE-443C-AA77-E3B7BF6F2295}").ToString("B");

    protected DateTimeOffset Now { get; set; } = default!;
    protected CertificateOptions? Order { get; set; } = default!;
    protected DeploymentOptions Deploy { get; set; } = default!;
    protected DeploymentTarget Target { get; set; } = default!;
    protected int Phase { get; set; }

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

    protected async Task<DateTimeOffset?> UpdateCertificateAsync(CancellationToken cancellationToken)
    {
        try
        {
            var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
            var certificate = pfx == null ? null : new X509Certificate2(pfx, PfxPassword);

            var lifetime = 0.0;
            var renewalDate = DateTimeOffset.UtcNow;

            LoggerContext.Set("Order", OrderId);

            if (certificate != null)
            {
                LoggerContext.Set("Thumbprint", certificate.Thumbprint);
                LoggerContext.Set("Start", certificate.NotBefore.ToString("dd-MM-yyy HH:mm::ss") + " UTC");
                LoggerContext.Set("Expiration", certificate.NotAfter.ToString("dd-MM-yyy HH:mm::ss") + " UTC");

                lifetime = (certificate.NotAfter - certificate.NotBefore).TotalDays;
                renewalDate = (DateTimeOffset)certificate.NotBefore.ToUniversalTime() + TimeSpan.FromDays(lifetime * Order.RenewalFactor);
            }

            if (certificate != null && DateTimeOffset.UtcNow > renewalDate)
            {
                Logger.Information($"Existing certificates lifetime has exceeded {Order.RenewalFactor * 100}%. Removing it now");
                CertificateService.DeleteOrder(OrderId);
                CertificateService.DeleteCertificate(OrderId);
                certificate = null;
            }

            if (certificate != null)
            {
                Logger.Information($"Existing certificate is still valid. Recheck at {renewalDate}");
                return renewalDate;
            }

            if (!await CertificateService.UpdateOrCreateCertificate(OrderId, Order, cancellationToken))
                return Now + TimeSpan.FromHours(1);

            pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
            certificate = pfx == null ? null : new X509Certificate2(pfx, PfxPassword);

            LoggerContext.Set("Thumbprint", certificate?.Thumbprint);

            if (certificate == null)
                return Now + TimeSpan.FromHours(1);

            lifetime = (certificate.NotAfter - certificate.NotBefore).TotalDays;
            renewalDate = (DateTimeOffset)certificate.NotBefore.ToUniversalTime() + TimeSpan.FromDays(lifetime * Order.RenewalFactor);

            Logger.Information($"Got new certificate. Recheck at {renewalDate}");

            return renewalDate;
        }
        catch (Exception ex)
        {
            var message = $"Certificate update failed for order {OrderId}";

            Logger.Error(ex, message);

            await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);

            return DateTimeOffset.Now + TimeSpan.FromHours(1);
        }
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

        if( Username != null && Password != null )
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

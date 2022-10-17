using System.IO;
using System.Security;
using System.Text;
using System.Threading;

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
    // protected string? UncPath { get; set; }
    protected string? LocalPath { get; set; }

    protected string GetLocalCertificatePath()
        => Path.Join(LocalPath, $"{OrderId}.pfx");

    //protected string GetNetworkCertificatePath()
    //    => Path.Join(UncPath, $"{OrderId}.pfx");

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

    //protected async Task<byte[]?> CopyCertificateAsync(CancellationToken cancellationToken)
    //{
    //    var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
    //    if (pfx == null) return null;

    //    var filePathUnc = GetNetworkCertificatePath();
    //    var directoryUnc = Path.GetDirectoryName(filePathUnc);

    //    if (directoryUnc != null && !Directory.Exists(directoryUnc))
    //        Directory.CreateDirectory(directoryUnc);

    //    await File.WriteAllBytesAsync(filePathUnc, pfx, cancellationToken);

    //    return pfx;
    //}

    protected async Task<bool> CopyCertificateAsync(CancellationToken cancellationToken)
    {
        var sourcepath = Path.Join(CertificateService.CertificatePath, $"{OrderId}.pfx");
        if (!File.Exists(sourcepath)) return false;

        var targetpath = GetLocalCertificatePath();

        var script = new StringBuilder();
        if (!string.IsNullOrEmpty(Username))
        {
            script.AppendLine($"$pw = convertto-securestring -AsPlainText -Force -String '{Password}'");
            script.AppendLine($"$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist '{Username}',$pw");
            script.AppendLine($"$session = New-PSSession -ComputerName {ComputerName} -Credential $cred");
        } else script.AppendLine($"$session = New-PSSession -ComputerName {ComputerName}");
        script.AppendLine( $"Copy-Item -Path '{sourcepath}' -Destination '{LocalPath}' -ToSession $session");
        script.AppendLine($"Remove-PSSession -Session $session");

        await RunLocalScriptAsync(script.ToString(), cancellationToken);

        return true;
    }

    protected async Task SetRegistryKeyAsync( string path, string name, string value, CancellationToken cancellationToken )
    {
        var script = new StringBuilder();
        script.AppendLine($"$path = 'Registry::{path}'");
        script.AppendLine($"$name = '{name}'");
        script.AppendLine($"$value = '{value}'");
        script.AppendLine($"If( -not (Test-Path $path) ) {{ New-Item -Path $path -Force | Out-Null }}");
        script.AppendLine($"New-ItemProperty -Path $path -Name $name -Value $value -Force");

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }

    protected async Task AddAccessRightsToCertificateAsync( string storeName, string thumbprint, string username, CancellationToken cancellationToken )
    {
        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine(
            $"$certs = Get-ChildItem 'Cert:\\LocalMachine\\{storeName}' | " +
            $"Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }} | " +
            $"Select-Object -first 1");
        script.AppendLine($"$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certs[0])");
        script.AppendLine($"$rule = New-Object System.Security.AccessControl.FileSystemAccessRule '{username}', Read, Allow");
        script.AppendLine($"$filepath = [io.path]::combine($env:ALLUSERSPROFILE, 'Microsoft\\Crypto\\Keys', $key.key.UniqueName)");
        script.AppendLine($"$acl = Get-Acl -path $filepath");
        script.AppendLine($"$acl.AddAccessRule($rule)");
        script.AppendLine($"Set-Acl $filepath $acl");

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }

    protected async Task ChangePasswordCertificateAsync(string password, CancellationToken cancellationToken)
    {
        var filePathLocal = GetLocalCertificatePath();
        var filePathTemp = Path.Combine(Path.GetDirectoryName(filePathLocal)!, "temp.pfx");

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"$newpassword = ConvertTo-SecureString -String '{password}' -Force -AsPlainText");
        script.AppendLine($"$oldpassword = ConvertTo-SecureString -String '{PfxPassword}' -Force -AsPlainText");
        script.AppendLine($"$pfx = Get-PfxData -FilePath '{filePathLocal}' -Password $oldpassword");
        script.AppendLine($"Export-PfxCertificate -PFXData $pfx -FilePath {filePathTemp} -Password $newpassword");
        script.AppendLine($"Remove-Item -Path '{filePathLocal}' -Force");
        script.AppendLine($"Rename-Item -Path '{filePathTemp}' -NewName '{filePathLocal}' -Force");

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }

    protected async Task ImportCertificateAsync(string storeName, CancellationToken cancellationToken)
    {
        var thumbprint = await GetThumbprintAsync(cancellationToken);

        var filePathLocal = GetLocalCertificatePath();

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"Get-ChildItem 'cert:\\LocalMachine\\{storeName}' | Where-Object {{ $_.Subject -eq 'CN={DnsNames.First()}' -and $_.Thumbprint -ne '{thumbprint}' }} | Remove-Item");
        script.AppendLine($"Get-ChildItem 'cert:\\LocalMachine\\{storeName}' | Where-Object {{ $_.Subject -eq 'CN={DnsNames.First()}' -and $_.Thumbprint -eq '{thumbprint}' }}");
        var results = await RunRemoteScriptAsync(script.ToString(), cancellationToken);

        if (!results.Any(r => r.Contains(thumbprint)))
        {
            Logger.Information("Import certificate into remote store");

            script = new StringBuilder();
            script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
            script.AppendLine($"$certImportPwd = ConvertTo-SecureString -String '{PfxPassword}' -AsPlainText -Force");
            script.AppendLine($"Import-PfxCertificate -FilePath \"{filePathLocal}\" -CertStoreLocation \"cert:\\LocalMachine\\{storeName}\" -Password $certImportPwd -Exportable");
            await RunRemoteScriptAsync(script.ToString(), cancellationToken);
        }
    }

    protected async Task ExportCertificateAsync(string storeName, string password, bool chain, CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return;

        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        var filePathLocal = GetLocalCertificatePath();
        var chainOption = chain ? "BuildChain" : "EndEntityCertOnly";

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"$newpassword = ConvertTo-SecureString -String '{password}' -Force -AsPlainText");
        script.AppendLine($"$oldpassword = ConvertTo-SecureString -String '{PfxPassword}' -Force -AsPlainText");
        script.AppendLine($"Export-PfxCertificate -Cert 'cert:\\localmachine\\{storeName}\\{thumbprint}' -FilePath {filePathLocal} -Password $newpassword -ChainOption {chainOption} -Force");
        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }

    protected async Task RestartServiceAsync(string displayName, CancellationToken cancellationToken)
    {
        var script = new StringBuilder();

        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");

        script.AppendLine($"$timespan = New-Object -TypeName System.Timespan -ArgumentList 0,1,0");
        script.AppendLine($"$svc = Get-Service -DisplayName '{displayName}'");
        script.AppendLine($"if( ($svc -ne $null) -and ($svc.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) ) {{");
        script.AppendLine($"    $svc.Stop()");
        script.AppendLine($"    try {{");
        script.AppendLine($"        $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, $timespan)");
        script.AppendLine($"    }}");
        script.AppendLine($"    catch [ServiceProcess.TimeoutException] {{");        
        script.AppendLine($"        $pid = (get-wmiobject win32_service | where {{ $_.DisplayName -eq '{displayName}'}}).processID");
        script.AppendLine($"        Stop-Process -Id $pid -Force");
        script.AppendLine($"    }}");
        script.AppendLine($"}}");

        script.AppendLine($"Start-Service -DisplayName '{displayName}'");

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }

    protected async Task<string[]> RunLocalScriptAsync(string script, CancellationToken cancellationToken)
    {
        Runspace runspace = null!;
        return await runspace.ExecuteAsync(shell => shell.AddScript(script));
    }

    protected async Task<string[]> RunRemoteScriptAsync(string script, CancellationToken cancellationToken)
    {
        var connectionInfo = new WSManConnectionInfo();
        connectionInfo.ComputerName = ComputerName;

        if (Username != null && Password != null)
            connectionInfo.Credential = new PSCredential(Username, new NetworkCredential("", Password).SecurePassword);

        using var runspace = RunspaceFactory.CreateRunspace(connectionInfo);
        runspace.Open();

        try
        {
            return await runspace.ExecuteAsync(shell => shell.AddScript(script));
        }
        finally
        {
            runspace.Close();
        }        
    }

    protected async Task RemoteAsync(Func<Runspace, Task> tasks)
    {
        var connectionInfo = new WSManConnectionInfo();
        connectionInfo.ComputerName = ComputerName;

        if (Username != null && Password != null)
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

    public async Task<string> GetThumbprintAsync(CancellationToken cancellationToken)
    {
        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) throw new NullReferenceException($"No certificate stored with id {OrderId}");

        var certificate = new X509Certificate2(pfx, PfxPassword);

        return certificate.Thumbprint;
    }
}

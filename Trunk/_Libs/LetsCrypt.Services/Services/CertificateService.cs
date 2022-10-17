using ACMESharp.Authorizations;
using ACMESharp.Protocol;
using ACMESharp.Protocol.Resources;
using DnsClient;
using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using PKISharp.SimplePKI;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

[Singleton]
internal class CertificateService
{
    public const string ValidStatus = "valid";
    public const string InvalidStatus = "invalid";
    public const string PendingStatus = "pending";
    public const string ReadyStatus = "ready";

    private readonly ILogger Logger;
    private readonly IHttpClientFactory HttpFactory;
    private readonly IOptionsMonitor<AcmeOptions> AcmeOptions;
    private readonly IOptionsMonitor<PlatformOptions> PlatformOptions;
    private readonly IOptionsMonitor<NederhostOptions> NederhostOptions;
    private readonly IDnsHostingService DnsHostingService;

    public CertificateService(
        ILogger<CertificateService> logger,
        IHttpClientFactory httpFactory, 
        IOptionsMonitor<AcmeOptions> acmeOptions, 
        IOptionsMonitor<PlatformOptions> platformOptions,
        IDnsHostingService dnsHostingService)
    {
        Logger = logger;
        HttpFactory = httpFactory;
        AcmeOptions = acmeOptions;
        PlatformOptions = platformOptions;
        DnsHostingService = dnsHostingService;
    }

    public string CertificatePath
        => PlatformOptions.CurrentValue.SharedDataPath!;

    public async Task<bool> UpdateOrCreateCertificate(string id, CertificateOptions order, CancellationToken cancellationToken)
    {
        using var http = CreateHttpClient(cancellationToken);
        using var acme = await CreateAcmeClientAndAccount(http, cancellationToken);

        var details = await LoadOrderDetailsAsync(id, cancellationToken);
        
        if( details == null )
        {

            Logger.Information("Create new order details");
            details = await acme.CreateOrderAsync(order.DnsNames, null, null, cancellationToken);
            await SaveOrderDetailsAsync(id, details, cancellationToken);
            LoggerContext.Set("OrderDetails", details.OrderUrl);
            LoggerContext.Set("OrderExpires", details.Payload.Expires);
            Logger.Information("Created new order details");
        }
        else
        {
            Logger.Information("Load order details");
            details = await acme.GetOrderDetailsAsync(details.OrderUrl, existing: details, cancellationToken);
            await SaveOrderDetailsAsync(id, details, cancellationToken);
            LoggerContext.Set("OrderDetails", details.OrderUrl);
            LoggerContext.Set("OrderExpires", details.Payload.Expires);
            Logger.Information("Loaded existing order details");
        }

        if (details.Payload.Status == InvalidStatus)
        {
            Logger.Warning($"Order has state invalid. Order deleted");
            var path = Path.Combine(CertificatePath, $"Order {id}.json");
            File.Delete(path);
            return false;
        }

        if (details.Payload.Status == PendingStatus || details.Payload.Status == ReadyStatus )
        {
            Logger.Information($"Order has pending validation");

            foreach (var url in details.Payload.Authorizations)
            {
                var authorization = await acme.GetAuthorizationDetailsAsync(url, cancellationToken);
                if (authorization.Status == ValidStatus) continue;

                var challenge = authorization.Challenges.First(c => c.Type == Dns01ChallengeValidationDetails.Dns01ChallengeType);

                var dns = (Dns01ChallengeValidationDetails)AuthorizationDecoder.DecodeChallengeValidation(authorization, challenge.Type, acme.Signer);

                var values = new[] { new DnsValue { content = dns.DnsRecordValue } };

                await DnsHostingService.SetRecordAsync(
                    order.DnsHostingProvider, 
                    order.DnsHostingZone, 
                    dns.DnsRecordName, 
                    dns.DnsRecordType, 
                    values, 
                    cancellationToken);

                if (order.DnsUpdateValidation )
                {
                    var options = new LookupClientOptions();
                    options.UseCache = false;

                    var lookup = new LookupClient();
                    await WaitForAsync(async () =>
                    {
                        var answer = await lookup.QueryAsync(dns.DnsRecordName, QueryType.TXT);
                        return answer.Answers.TxtRecords().Any(t => t.EscapedText.Any(e => e == dns.DnsRecordValue));
                    }, cancellationToken);

                }
                
                await Task.Delay(order.DnsUpdateDelay, cancellationToken);

                await acme.GetNonceAsync();
                challenge = await acme.AnswerChallengeAsync(challenge.Url, cancellationToken);

                await WaitForAsync(async () =>
                {
                    await acme.GetNonceAsync();
                    challenge = await acme.GetChallengeDetailsAsync(challenge.Url, cancellationToken);
                    return challenge.Status == ValidStatus;
                }, cancellationToken);

                await DnsHostingService.DeleteRecordAsync(
                    order.DnsHostingProvider,
                    order.DnsHostingZone,
                    dns.DnsRecordName, 
                    dns.DnsRecordType, 
                    cancellationToken);
            }

            await WaitForAsync(async () =>
            {
                foreach (var url in details.Payload.Authorizations)
                {
                    var authorization = await acme.GetAuthorizationDetailsAsync(url, cancellationToken);
                    if (authorization.Status != ValidStatus) return false;
                }
                return true;

            }, cancellationToken);

            Logger.Information($"Order validated, create public/private key pair");

            var keypair = CreateKeyPair(order);
            await SaveOrderKeyAsync(id, keypair, cancellationToken);

            Logger.Information($"Finalize Order");

            var request = CreateSigningRequest(order, keypair);
            details = await acme.FinalizeOrderAsync(details.Payload.Finalize, request, cancellationToken);
        }

        await WaitForAsync(async () =>
        {
            details = await acme.GetOrderDetailsAsync(details.OrderUrl, details, cancellationToken);
            return details.Payload.Status == ValidStatus && !string.IsNullOrEmpty(details.Payload.Certificate);
        }, cancellationToken);

        if( details.Payload.Status == ValidStatus)
        {
            Logger.Information($"Order finalized, get certificate");

            var key = await LoadOrderKeyAsync(id, cancellationToken);
            if (key == null) throw new Exception("Private key is missing");

            var response = await acme.GetAsync(details.Payload.Certificate);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsByteArrayAsync(cancellationToken);

            using var cert = new X509Certificate2(content);
            var certificate = PkiCertificate.From(cert);
            var pfx = certificate.Export(PkiArchiveFormat.Pkcs12, key.PrivateKey, null, order.PfxPassword?.ToCharArray());

            await SaveCertificateAsync(id, pfx, cancellationToken);

            LoggerContext.Set("Thumbprint", cert.Thumbprint);
            LoggerContext.Set("Start", cert.NotBefore.ToString("dd-MM-yyy HH:mm::ss") + " UTC");
            LoggerContext.Set("Expires", cert.NotAfter.ToString("dd-MM-yyy HH:mm::ss") + " UTC");
            Logger.Information($"Certificate stored");
        }

        return true;
    }

    public async Task EnsureAccount(CancellationToken cancellationToken)
    {
        using var http = CreateHttpClient(cancellationToken);
        using var acme = await CreateAcmeClientAndAccount(http, cancellationToken);
    }

    private PkiKeyPair CreateKeyPair(CertificateOptions order)
    {
        switch (order.KeyAlgorithm)
        {
            case KeyAlgorithms.Rsa:
                return PkiKeyPair.GenerateRsaKeyPair(order.KeySize);
            case KeyAlgorithms.Ec:
                return PkiKeyPair.GenerateEcdsaKeyPair(order.KeySize);
            default: throw new Exception($"Invalid key algorithm ({order.KeyAlgorithm})");
        }
    }

    private byte[] CreateSigningRequest(CertificateOptions order, PkiKeyPair keyPair)
    {
        var csr = new PkiCertificateSigningRequest($"CN={order.DnsNames.First()}", keyPair, PkiHashAlgorithm.Sha256);
        csr.CertificateExtensions.Add(PkiCertificateExtension.CreateDnsSubjectAlternativeNames(order.DnsNames));
        return csr.ExportSigningRequest(PkiEncodingFormat.Der);
    }

    private HttpClient CreateHttpClient(CancellationToken cancellationToken)
    {
        var http = HttpFactory.CreateClient();
        http.BaseAddress = new Uri(AcmeOptions.CurrentValue.Url ?? "https://acme-v02.api.letsencrypt.org/" );
        return http;
    }

    private async Task WaitForAsync( Func<Task<bool>> completed, CancellationToken cancellationToken)
    {
        TimeSpan delay = TimeSpan.FromSeconds(1);

        while (!await completed())
        {
            await Task.Delay(delay, cancellationToken);

            delay += TimeSpan.FromMilliseconds(500);
            if( delay > TimeSpan.FromSeconds(20) )
                delay = TimeSpan.FromSeconds(20);
        }
    }

    private async Task<AcmeProtocolClient> CreateAcmeClientAndAccount(HttpClient http, CancellationToken cancellationToken)
    {
        var directory = await LoadServiceDirectoryAsync(cancellationToken);
        var account = await LoadAccountDetailsAsync(cancellationToken);
        var key = await LoadAccountKeyAsync(cancellationToken);
        var signer = key?.CreateSigningTool();

        var acme = new AcmeProtocolClient(http, directory, account, signer, usePostAsGet: true);

        if (directory == null)
        {
            acme.Directory = await acme.GetDirectoryAsync(cancellationToken);
            await SaveServiceDirectoryAsync(acme.Directory, cancellationToken);
        }

        await acme.GetNonceAsync();

        if (acme.Account == null)
        {
            acme.Account = await acme.CreateAccountAsync(AcmeOptions.CurrentValue.EMailAddresses.Select(a => $"mailto:{a}"), true);
            await SaveAccountDetailsAsync(acme.Account, cancellationToken);

            key = new AccountKey { KeyType = acme.Signer.JwsAlg, KeyExport = acme.Signer.Export() };
            await SaveAccountKeyAsync(key, cancellationToken);
        }

        return acme;
    }


    private async Task<ServiceDirectory?> LoadServiceDirectoryAsync(CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, "ServiceDirectory.json");
        if (!File.Exists(path)) return null;

        var text = await File.ReadAllTextAsync(path, cancellationToken);

        return JsonConvert.DeserializeObject<ServiceDirectory>(text);
    }

    private async Task<AccountDetails?> LoadAccountDetailsAsync(CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, "AccountDetails.json");
        if (!File.Exists(path)) return null;

        var text = await File.ReadAllTextAsync(path, cancellationToken);

        return JsonConvert.DeserializeObject<AccountDetails>(text);
    }

    private async Task<AccountKey?> LoadAccountKeyAsync(CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, "AccountKey.json");
        if (!File.Exists(path)) return null;

        var text = await File.ReadAllTextAsync(path, cancellationToken);

        return JsonConvert.DeserializeObject<AccountKey>(text);
    }

    private async Task<OrderDetails?> LoadOrderDetailsAsync(string id, CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, $"Order {id}.json");
        if (!File.Exists(path)) return null;

        var text = await File.ReadAllTextAsync(path, cancellationToken);

        return JsonConvert.DeserializeObject<OrderDetails>(text);
    }

    private async Task<PkiKeyPair?> LoadOrderKeyAsync(string id, CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, $"OrderKey {id}.xml");
        if (!File.Exists(path)) return null;

        var bytes = await File.ReadAllBytesAsync(path, cancellationToken);

        using var stream = new MemoryStream(bytes);

        return PkiKeyPair.Load(stream);
    }

    private async Task SaveServiceDirectoryAsync(ServiceDirectory directory, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, "ServiceDirectory.json");

        var text = JsonConvert.SerializeObject( directory, Formatting.Indented );
        
        await File.WriteAllTextAsync(path, text, cancellationToken);
    }

    private async Task SaveAccountDetailsAsync(AccountDetails details, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, "AccountDetails.json");

        var text = JsonConvert.SerializeObject(details, Formatting.Indented);

        await File.WriteAllTextAsync(path, text, cancellationToken);
    }

    private async Task SaveAccountKeyAsync(AccountKey key, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, "AccountKey.json");

        var text = JsonConvert.SerializeObject(key, Formatting.Indented);

        await File.WriteAllTextAsync(path, text, cancellationToken);
    }

    private async Task SaveOrderDetailsAsync(string id, OrderDetails details, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, $"Order {id}.json");

        var text = JsonConvert.SerializeObject(details, Formatting.Indented);

        await File.WriteAllTextAsync(path, text, cancellationToken);
    }

    private async Task SaveOrderKeyAsync(string id, PkiKeyPair key, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, $"OrderKey {id}.xml");

        using var stream = new MemoryStream();
        key.Save(stream);

        await File.WriteAllBytesAsync(path, stream.ToArray(), cancellationToken);
    }

    private async Task SaveCertificateAsync(string id, byte[] data, CancellationToken cancellationToken)
    {
        if (!Directory.Exists(PlatformOptions.CurrentValue.SharedDataPath))
            Directory.CreateDirectory(CertificatePath);

        var path = Path.Combine(CertificatePath, $"{id}.pfx");

        await File.WriteAllBytesAsync(path, data, cancellationToken);
    }

    public async Task<byte[]?> LoadCertificateAsync(string id, CancellationToken cancellationToken)
    {
        var path = Path.Combine(CertificatePath, $"{id}.pfx");
        if (!File.Exists(path)) return null;

        return await File.ReadAllBytesAsync(path, cancellationToken);
    }

    public void DeleteOrder(string id)
    {
        var path = Path.Combine(CertificatePath, $"Order {id}.json");
        if (!File.Exists(path)) return;

        File.Delete(path);
    }

    public void DeleteCertificate(string id)
    {
        var path = Path.Combine(CertificatePath, $"{id}.pfx");
        if (!File.Exists(path)) return;

        File.Delete(path);
    }
}

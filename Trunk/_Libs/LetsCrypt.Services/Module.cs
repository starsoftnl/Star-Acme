global using System.Net;
global using System.Management.Automation;
global using System.Management.Automation.Runspaces;
global using System.Net.Http.Json;
global using System.Security.Cryptography.X509Certificates;

global using Microsoft.Extensions.Options;
global using Microsoft.Extensions.Logging;
global using Microsoft.Extensions.DependencyInjection;

global using Platform.Mail;
global using Platform.Hosting;
global using Platform.Hosting.Tasks;
global using Platform.DependencyInjection;
global using Platform.Extensions;
global using Platform.Logging;

global using LetsCrypt.Services.Models;
global using LetsCrypt.Services.Options;
global using LetsCrypt.Services.Clients;
global using LetsCrypt.Services.Services;

namespace LetsCrypt.Services;

public class Module : IConfigureServices
{
    public void ConfigureServices(IConfigureServicesContext context, IServiceCollection services)
    {
        services.AddHttpClient();
    }
}


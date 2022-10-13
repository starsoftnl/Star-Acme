using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Platform.Hosting;
using Platform.Logging;

try
{
    SimpleFileLogger.WriteLine("Starting application 1");

    var host = PlatformConsoleApplication.CreateBuilder(typeof(Program).Assembly);

    SimpleFileLogger.WriteLine("Starting application 2");

    host
        // .UseRegistration(DbContextRegistration.AddDbContextsInAssembly)
        .UseRegistration(HttpClientRegistration.AddHttpClientsInAssembly)
        .AddAssembly(typeof(Platform.Services.Module))
        .AddAssembly(typeof(Platform.Mail.Module))
        .AddAssembly(typeof(Platform.Hosting.Module))
        .AddAssembly(typeof(Platform.Hosting.Console.Module))
        .AddAssembly(typeof(Platform.WindowsService.Module))
        .AddAssembly(typeof(LetsCrypt.Module))
        .AddAssembly(typeof(LetsCrypt.Services.Module))
        .AddAssembly();

    SimpleFileLogger.WriteLine("Starting application 3");

    var app = host.Build();

    SimpleFileLogger.WriteLine("Starting application 4");

    var result = await app.ExecuteApplicationStartHandlersAsync(default);

    SimpleFileLogger.WriteLine("Starting application 5");

    if (result) await app.RunAsync(default);

    SimpleFileLogger.WriteLine("Starting application 6");

    return result ? 0 : -1;
}
catch ( Exception ex )
{
    SimpleFileLogger.WriteLine("Starting application 5");

    SimpleFileLogger.WriteLine(ex.ToText());

    return -2;
}
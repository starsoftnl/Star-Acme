var host = PlatformConsoleApplication.CreateBuilder(typeof(Program).Assembly);

host
    // .UseRegistration(DbContextRegistration.AddDbContextsInAssembly)
    .UseRegistration(HttpClientRegistration.AddHttpClientsInAssembly)
    .AddAssembly(typeof(Platform.Services.Module))
    .AddAssembly(typeof(LetsCrypt.Module))
    .AddAssembly(typeof(LetsCrypt.Services.Module))
    .AddAssembly();

await host.RunAsync(default);

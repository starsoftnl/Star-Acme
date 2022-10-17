namespace LetsCrypt.Services.Options;

internal class DeploymentOptions
{
    public string? Name { get; set; }

    public string Certificate { get; set; } = default!;

    public string? Username { get; set; }

    public string? Password { get; set; }

    // public string UncPath { get; set; } = "\\\\{ComputerName}\\C$\\admin\\Certificate";

    public string LocalPath { get; set; } = "c:\\admin\\Certificate";

    public string[] IncludeTargets { get; set; } = new string[0];

    public string[] ExcludeTargets { get; set; } = new string[0];

    public Dictionary<string, DeploymentTarget> Targets { get; set; } = new();
}

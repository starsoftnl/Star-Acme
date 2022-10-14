namespace LetsCrypt.Services.Models;

internal class DeploymentTargetAuthentication
{
    public string NetworkShare { get; set; } = default!;

    public string? Domain { get; set; }

    public string Username { get; set; } = default!;

    public string? Password { get; set; }
}

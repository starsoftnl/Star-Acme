namespace LetsCrypt.Services.Models;

internal class DeploymentTargetBase
{
    public int Phase { get; set; } = 0;
    public bool Enabled { get; set; } = true;
    public string StoreName { get; set; } = "My";
}

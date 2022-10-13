using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using static System.Net.Mime.MediaTypeNames;

namespace LetsCrypt.Services;

internal class LetsCryptMailService : ILetsCryptMailService
{
    private readonly ILogger Logger;
    private readonly IEMailService MailService;

    public LetsCryptMailService(
        IEMailService mailService,
        ILogger<DeploymentService> logger)
    {
        Logger = logger;
        MailService = mailService;
    }

    public async Task SendEmailNotificationAsync(
        Exception error, 
        string message, 
        CancellationToken cancellationToken, 
        [CallerMemberName] string filename = default!, 
        [CallerLineNumber] int linenumber = 0)
    {
        try
        {
            var text = new StringBuilder(message);
            text.AppendLine();
            text.AppendLine();
            text.AppendLine($"Source Code: {filename}");
            text.AppendLine($"Source Line: {linenumber}");
            text.AppendLine();
            text.AppendLine("Error Message:");
            text.AppendLine();
            text.AppendLine(error.ToText());

            await MailService.SendAsync("Lets Encrypt Certificate Update Failed", text.ToString(), cancellationToken);
        }
        catch (Exception ex)
        {
            Logger.Warning(ex, "EMail notification failed");
        }
    }

    public async Task SendEmailNotificationAsync(string message, CancellationToken cancellationToken)
    {
        try
        {
            await MailService.SendAsync("Lets Encrypt Certificate Update", message, cancellationToken);
        }
        catch (Exception ex)
        {
            Logger.Warning(ex, "EMail notification failed");
        }
    }
}


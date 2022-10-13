using System.Runtime.CompilerServices;

namespace LetsCrypt.Services;

internal interface ILetsCryptMailService
{
    Task SendEmailNotificationAsync(
        Exception ex,
        string message,
        CancellationToken cancellationToken,
        [CallerMemberName] string filename = default!,
        [CallerLineNumber] int linenumber = default);

    Task SendEmailNotificationAsync( string message, CancellationToken cancellationToken);
}


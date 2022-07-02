using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace LetsCrypt.Services;

internal static class PowershellExtensions
{
    public static async Task<string[]> ExecuteAsync(this Runspace runspace, Action<PowerShell> commands, ILogger? logger = null)
    {
        using var shell = PowerShell.Create();

        shell.Runspace = runspace;

        commands(shell);

        var results = await shell.InvokeAsync();

        if( shell.HadErrors )
            throw new AggregateException("Powershell command failed. See the inner exceptions for details", shell.Streams.Error.Select(e => e.Exception) );

        var texts = results.Select(s => s.ToString()).ToArray();

        if( logger != null )
            foreach( var text in texts ) 
                logger.Debug(text);

        return texts;
    }

    public static async Task<string[]> SafeExecuteAsync(this Runspace runspace, Action<PowerShell> commands, ILogger? logger = null)
    {
        using var shell = PowerShell.Create();

        shell.Runspace = runspace;

        commands(shell);

        var results = await shell.InvokeAsync();

        var texts = results.Select(s => s.ToString()).ToArray();

        if (logger != null)
            foreach (var text in texts)
                logger.Debug(text);

        return texts;
    }

    public static void AddExpression(this PowerShell shell, string expression)
    {
        shell.AddCommand("Invoke-Expression").AddArgument(expression);
    }
}
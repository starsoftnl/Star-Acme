using ACMESharp.Crypto.JOSE;
using LetsCrypt.Services.Models;

namespace LetsCrypt.Services;

internal static class AccountKeyExtensions
{
    public static IJwsTool CreateSigningTool( this AccountKey key )
    {
        if( key == null ) 
            throw new ArgumentNullException( "key" );

        if (key.KeyType.StartsWith("ES"))
        {
            var tool = new ACMESharp.Crypto.JOSE.Impl.ESJwsTool();
            tool.HashSize = int.Parse(key.KeyType.Substring(2));
            tool.Init();
            tool.Import(key.KeyExport);
            return tool;
        }

        if (key.KeyType.StartsWith("RS"))
        {
            var tool = new ACMESharp.Crypto.JOSE.Impl.RSJwsTool();
            tool.HashSize = int.Parse(key.KeyType.Substring(2));
            tool.Init();
            tool.Import(key.KeyExport);
            return tool;
        }

        throw new Exception($"Unknown or unsupported KeyType [{key.KeyType}]");
    }
}
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;

namespace Incremental.Common.Authentication.Jwt;

public class TokenServiceOptionsPostConfigureOptions: IPostConfigureOptions<TokenServiceOptions>
{
    private readonly IConfiguration _configuration;

    public TokenServiceOptionsPostConfigureOptions(IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public void PostConfigure(string name, TokenServiceOptions options)
    {
        options.TokenIssuer ??= _configuration["JWT_TOKEN_ISSUER"];
        options.TokenSecurityKey ??= _configuration["JWT_TOKEN_SECURITY_KEY"];
    }
}
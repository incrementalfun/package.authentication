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

    public void PostConfigure(string? name, TokenServiceOptions options)
    {
        if (!string.IsNullOrWhiteSpace(_configuration["JWT_LIFETIME"]))
        {
            var lifetime = TimeSpan.FromMinutes(_configuration.GetValue<int>("JWT_LIFETIME"));
            if (lifetime.TotalMinutes >= 1)
            {
                options.TokenLifetime = lifetime;
            }
        }
        
        options.TokenIssuer ??= _configuration["JWT_TOKEN_ISSUER"];
        options.TokenSecurityKey ??= _configuration["JWT_TOKEN_SECURITY_KEY"];
    }
}
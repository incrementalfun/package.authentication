namespace Incremental.Common.Authentication.Jwt;

public class TokenServiceOptions
{
    public static string TokenService => nameof(TokenService);

    public TokenServiceOptions()
    {
        ApplicationLoginProvider = "application_identity";
        RefreshTokenLifetime = TimeSpan.FromDays(30);
        TokenLifetime = TimeSpan.FromMinutes(5);
    }

    /// <summary>
    /// Configures the token provider name used for storing refresh tokens.
    /// <remarks>
    /// Defaults to "application_provider".
    /// </remarks>
    /// </summary>
    public string ApplicationLoginProvider { get; set; }
    
    /// <summary>
    /// Lifetime of the JWT token in minutes.
    /// <remarks>
    /// Defaults to 5 minutes (5).
    /// </remarks>
    /// </summary>
    public TimeSpan TokenLifetime { get; set; }
    
    /// <summary>
    /// Lifetime of the refresh token in minutes.
    /// <remarks>
    /// Defaults to 30 days (43200).
    /// </remarks>
    /// </summary>
    public TimeSpan RefreshTokenLifetime { get; set; }
    
    /// <summary>
    /// Issuer of the JWT token.
    /// <remarks>
    /// If using the Incremental.Common.Authentication package there is no need to fill this property.
    /// It will be sourced automatically.
    /// </remarks>
    /// </summary>
    public string? TokenIssuer { get; set; }
    
    /// <summary>
    /// Security key to handle token signing.
    /// <remarks>
    /// If using the Incremental.Common.Authentication package there is no need to fill this property.
    /// It will be sourced automatically.
    /// </remarks>
    /// </summary>
    public string? TokenSecurityKey { get; set; }
}
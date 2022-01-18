namespace Incremental.Common.Authentication.Jwt;

public class TokenServiceOptions
{
    public static string TokenService => nameof(TokenService);

    public TokenServiceOptions()
    {
        ApplicationLoginProvider = "application_identity";
        RefreshTokenLifetime = 43200;
        TokenLifetime = 5;
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
    public int TokenLifetime { get; set; }
    
    /// <summary>
    /// Lifetime of the refresh token in minutes.
    /// <remarks>
    /// Defaults to 30 days (43200).
    /// </remarks>
    /// </summary>
    public int RefreshTokenLifetime { get; set; }
}
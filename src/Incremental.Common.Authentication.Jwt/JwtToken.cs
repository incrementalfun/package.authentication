namespace Incremental.Common.Authentication.Jwt;

/// <summary>
/// Represents a JWT token and a refresh token.
/// </summary>
public record JwtToken
{
    /// <summary>
    /// JWT token.
    /// </summary>
    public string Token { get; init; }
    
    /// <summary>
    /// Refresh token.
    /// </summary>
    public Guid RefreshToken { get; init; }
}
using System.Security.Claims;

namespace Incremental.Common.Authentication.Jwt;

public interface ITokenService
{
    Task<JwtToken> GenerateTokenAsync(string? userId, IEnumerable<string>? audiences = default);
    
    Task<JwtToken> GenerateTokenAsync(string userId, string audience);
    
    Task<JwtToken?> RefreshTokenAsync(JwtToken token);
    
    Task RevokeRefreshTokensAsync(string userId);
    
    ClaimsPrincipal? RetrieveClaimsPrincipal(JwtToken token);
}
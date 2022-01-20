using System.Security.Claims;

namespace Incremental.Common.Authentication.Jwt;

public interface ITokenService
{
    Task<JwtToken> GenerateToken(string userId, IEnumerable<string>? audiences = default);
    
    Task<JwtToken?> RefreshToken(JwtToken token);

    Task RevokeRefreshTokens(string userId);
}
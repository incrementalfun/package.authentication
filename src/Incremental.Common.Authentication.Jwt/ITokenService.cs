using System.Security.Claims;

namespace Incremental.Common.Authentication.Jwt;

public interface ITokenService
{
    Task<JwtToken> GenerateToken(string userId, string? audience, Claim[]? additionalClaims = default);
    
    Task<JwtToken?> RefreshToken(JwtToken token, Claim[]? additionalClaims = default);
}
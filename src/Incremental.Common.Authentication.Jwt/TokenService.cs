using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Incremental.Common.Authentication.Jwt;

public class TokenService<TUser> : ITokenService where TUser : IdentityUser
{
    private readonly ILogger<TokenService<TUser>> _logger;
    private readonly UserManager<TUser> _userManager;
    private readonly JwtBearerOptions _jwtBearerOptions;
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly AspNetUserManager<TUser> _test;

    public TokenService(ILogger<TokenService<TUser>> logger, UserManager<TUser> userManager, IOptions<JwtBearerOptions> jwtBearerOptions)
    {
        _logger = logger;
        _userManager = userManager;
        _jwtBearerOptions = jwtBearerOptions.Value;

        _signingCredentials = new SigningCredentials(_jwtBearerOptions.TokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);
        _issuer = _jwtBearerOptions.TokenValidationParameters.ValidIssuer;
    }

    public async Task<JwtToken> GenerateToken(string userId, string? audience, Claim[]? additionalClaims = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        var claims = await _userManager.GetClaimsAsync(user) as List<Claim>;

        if (additionalClaims is not null)
        {
            claims?.AddRange(additionalClaims);
        }

        audience ??= _jwtBearerOptions.Audience;

        var token = GenerateJwtSecurityToken(audience, claims);
        var refreshToken = Guid.NewGuid().ToString();
        await _userManager.SetAuthenticationTokenAsync(user, "application_identity", "refresh_token", refreshToken);

        return new JwtToken
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken
        };
    }

    private JwtSecurityToken GenerateJwtSecurityToken(string? audience, IEnumerable<Claim>? claims)
    {
        return new JwtSecurityToken(_issuer, audience, claims, DateTime.UtcNow, DateTime.UtcNow.AddDays(1), _signingCredentials);
    }

    public async Task<JwtToken?> RefreshToken(JwtToken token, Claim[]? additionalClaims = default)
    {
        throw new NotImplementedException();
    }
}
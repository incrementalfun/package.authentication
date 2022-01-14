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
    private readonly JwtSecurityTokenHandler _securityTokenHandler;
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;

    private const string APPLICATION_LOGIN_PROVIDER = "application_identity";
    
    public TokenService(ILogger<TokenService<TUser>> logger, UserManager<TUser> userManager, IOptions<JwtBearerOptions> jwtBearerOptions)
    {
        _logger = logger;
        _userManager = userManager;
        _jwtBearerOptions = jwtBearerOptions.Value;

        _securityTokenHandler = new JwtSecurityTokenHandler();
        _signingCredentials = new SigningCredentials(_jwtBearerOptions.TokenValidationParameters.IssuerSigningKey, SecurityAlgorithms.HmacSha256);
        _issuer = _jwtBearerOptions.TokenValidationParameters.ValidIssuer;
    }

    public async Task<JwtToken> GenerateToken(string userId, string? audience = default, Claim[]? additionalClaims = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        var claims = await _userManager.GetClaimsAsync(user) as List<Claim>;

        if (additionalClaims is not null)
        {
            claims?.AddRange(additionalClaims);
        }

        audience ??= _jwtBearerOptions.Audience;

        var token = GenerateJwtSecurityToken();
        var refreshToken = Guid.NewGuid();
        await _userManager.SetAuthenticationTokenAsync(
            user: user,
            loginProvider: "application_identity",
            tokenName: APPLICATION_LOGIN_PROVIDER, 
            tokenValue: DateTime.UtcNow.AddDays(30).Ticks.ToString());

        return new JwtToken
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken
        };
        
        JwtSecurityToken GenerateJwtSecurityToken()
        {
            return new JwtSecurityToken(_issuer, audience, claims, DateTime.UtcNow, DateTime.UtcNow.AddDays(1), _signingCredentials);
        }
    }
    
    public async Task<JwtToken?> RefreshToken(JwtToken token, Claim[]? additionalClaims = default)
    {
        var validationParameters = _jwtBearerOptions.TokenValidationParameters;
        validationParameters.ValidateLifetime = false;

        var principal = _securityTokenHandler.ValidateToken(token.Token, validationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
        {
            return default;
        }

        if (principal is null)
        {
            return default;
        }

        var user = await _userManager.FindByIdAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier));

        if (user is null)
        {
            return default;
        }

        var refreshTokenLifetime = await RetrieveRefreshTokenLifetimeAsync();

        if (refreshTokenLifetime?.CompareTo(DateTime.UtcNow) >= 0)
        {
            await RemoveRefreshTokenAsync();

            return default;
        }

        var refreshedToken = await GenerateToken(user.Id, jwtSecurityToken.Audiences.FirstOrDefault());
        
        await RemoveRefreshTokenAsync();

        return refreshedToken;

        async Task<DateTime?> RetrieveRefreshTokenLifetimeAsync()
        {
            var information = await _userManager.GetAuthenticationTokenAsync(user, APPLICATION_LOGIN_PROVIDER, RefreshToken(token.RefreshToken));
            return information is null ? default(DateTime?) : new DateTime(Convert.ToInt64(information));
        }

        async Task RemoveRefreshTokenAsync()
        {
            await _userManager.RemoveAuthenticationTokenAsync(user, APPLICATION_LOGIN_PROVIDER, RefreshToken(token.RefreshToken));
        }
    }
    
    private static string RefreshToken(Guid refreshTokenId) => $"refresh_token:{refreshTokenId}";
}
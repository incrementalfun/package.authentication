using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Incremental.Common.Authentication.Jwt;

public class TokenService<TUser, TContext> : ITokenService
    where TUser : IdentityUser
    where TContext : IdentityDbContext<TUser>
{
    private readonly ILogger<TokenService<TUser, TContext>> _logger;
    private readonly UserManager<TUser> _userManager;
    private readonly TContext _context;
    private readonly JwtBearerOptions _jwtBearerOptions;
    private readonly TokenServiceOptions _tokenServiceOptions;
    private readonly JwtSecurityTokenHandler _securityTokenHandler;
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;

    public TokenService(ILogger<TokenService<TUser, TContext>> logger, UserManager<TUser> userManager, TContext context,
        IOptions<JwtBearerOptions> jwtBearerOptions, IOptions<TokenServiceOptions> tokenServiceOptions)
    {
        _logger = logger;
        _userManager = userManager;
        _context = context;
        _jwtBearerOptions = jwtBearerOptions.Value;
        _tokenServiceOptions = tokenServiceOptions.Value;

        _securityTokenHandler = new JwtSecurityTokenHandler();
        var securityKey = Encoding.UTF8.GetBytes(_tokenServiceOptions.TokenSecurityKey ??
                                                 throw new ArgumentNullException(nameof(_tokenServiceOptions.TokenSecurityKey)));
        _signingCredentials = new SigningCredentials(new SymmetricSecurityKey(securityKey), SecurityAlgorithms.HmacSha256);
        _issuer = _tokenServiceOptions.TokenIssuer ?? throw new ArgumentNullException(nameof(_tokenServiceOptions.TokenIssuer));
    }

    public async Task<JwtToken> GenerateTokenAsync(string? userId, IEnumerable<string>? audiences = default)
    {
        _logger.LogInformation("Start to generate JWT token for user with id {UserId}", userId);
        
        var user = await _userManager.FindByIdAsync(userId);
        var claims = await _userManager.GetClaimsAsync(user) as List<Claim>;

        if (audiences is not null)
        {
            _logger.LogInformation("JWT token will have the following audiences: {@Audiences}", audiences);
            
            claims?.AddRange(audiences.Select(audience => new Claim(JwtRegisteredClaimNames.Aud, audience)));
        }

        var token = GenerateJwtSecurityToken();
        
        var refreshToken = Guid.NewGuid();

        await StoreRefreshTokenAsync(refreshToken);
        
        return new JwtToken
        {
            Token = new JwtSecurityTokenHandler().WriteToken(token),
            RefreshToken = refreshToken
        };

        JwtSecurityToken GenerateJwtSecurityToken()
        {
            var generatedToken =  new JwtSecurityToken(
                issuer: _issuer,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.Add(_tokenServiceOptions.TokenLifetime),
                signingCredentials: _signingCredentials);
            
            _logger.LogInformation("Generated JWT security token");

            return generatedToken;
        };

        async Task StoreRefreshTokenAsync(Guid guid)
        {
            await _userManager.SetAuthenticationTokenAsync(
                user: user,
                loginProvider: _tokenServiceOptions.ApplicationLoginProvider,
                tokenName: EncodeRefreshToken(guid),
                tokenValue: DateTime.UtcNow.Add(_tokenServiceOptions.RefreshTokenLifetime).Ticks.ToString());
            
            _logger.LogInformation("Stored refresh token {RefreshToken}", refreshToken);
        }
    }

    public Task<JwtToken> GenerateTokenAsync(string userId, string audience)
    {
        return GenerateTokenAsync(userId, new[] { audience });
    }

    public async Task<JwtToken?> RefreshTokenAsync(JwtToken token)
    {
        _logger.LogInformation("Start to refresh JWT token with refresh token {RefreshToken}", token.RefreshToken);

        var validationParameters = _jwtBearerOptions.TokenValidationParameters;
        validationParameters.ValidateLifetime = false;
        validationParameters.ValidateAudience = false;
        validationParameters.ValidIssuer = _issuer;
        validationParameters.IssuerSigningKey = _signingCredentials.Key;

        var principal = _securityTokenHandler.ValidateToken(token.Token, validationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
        {
            _logger.LogInformation("JWT security token was invalid, refresh aborted");

            return default;
        }

        if (principal is null)
        {
            _logger.LogInformation("Principal was invalid, refresh aborted");

            return default;
        }

        var user = await _userManager.FindByIdAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier));

        if (user is null)
        {
            _logger.LogWarning("User was not found will trying to refresh a JWT token, refresh aborted");

            return default;
        }

        var refreshTokenLifetime = await RetrieveRefreshTokenLifetimeAsync();

        if (refreshTokenLifetime is null)
        {
            _logger.LogInformation("The refresh token was not found, refresh aborted");

            return default;
        }
        
        if (refreshTokenLifetime.Value.CompareTo(DateTime.UtcNow) <= 0)
        {
            await RemoveRefreshTokenAsync();

            _logger.LogInformation("The lifetime of the refresh token is expired, refresh aborted and token removed");

            return default;
        }

        var refreshedToken = await GenerateTokenAsync(user.Id, jwtSecurityToken.Audiences);

        _logger.LogInformation("JWT token refresh was successful");
        
        await RemoveRefreshTokenAsync();

        _logger.LogInformation("Refresh token removed after successful usage");

        return refreshedToken;

        async Task<DateTime?> RetrieveRefreshTokenLifetimeAsync()
        {
            var information = await _userManager.GetAuthenticationTokenAsync(user, _tokenServiceOptions.ApplicationLoginProvider,
                EncodeRefreshToken(token.RefreshToken));
            return information is null ? default(DateTime?) : new DateTime(Convert.ToInt64(information));
        }

        async Task RemoveRefreshTokenAsync()
        {
            await _userManager.RemoveAuthenticationTokenAsync(user, _tokenServiceOptions.ApplicationLoginProvider,
                EncodeRefreshToken(token.RefreshToken));
        }
    }

    public async Task RevokeRefreshTokensAsync(string userId)
    {
        _logger.LogInformation("Start to revoked all refresh tokens for user with id {UserId}", userId);

        var refreshTokens = await _context.UserTokens
            .Where(token => token.UserId == userId)
            .Where(token => token.LoginProvider == _tokenServiceOptions.ApplicationLoginProvider)
            .Where(token => token.Name.StartsWith("refresh_token"))
            .ToListAsync();

        _context.RemoveRange(refreshTokens);

        await _context.SaveChangesAsync();
        
        _logger.LogInformation("Revoked all refresh tokens for user with id {UserId}", userId);
    }

    private static string EncodeRefreshToken(Guid refreshTokenId) => $"refresh_token:{refreshTokenId}";
}
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

    public async Task<JwtToken> GenerateToken(string userId, IEnumerable<string>? audiences = default)
    {
        var user = await _userManager.FindByIdAsync(userId);
        var claims = await _userManager.GetClaimsAsync(user) as List<Claim>;

        if (audiences is not null)
        {
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
            return new JwtSecurityToken(
                issuer: _issuer,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(_tokenServiceOptions.TokenLifetime),
                signingCredentials: _signingCredentials);
        };

        async Task StoreRefreshTokenAsync(Guid guid)
        {
            await _userManager.SetAuthenticationTokenAsync(
                user: user,
                loginProvider: _tokenServiceOptions.ApplicationLoginProvider,
                tokenName: EncodeRefreshToken(guid),
                tokenValue: DateTime.UtcNow.AddMinutes(_tokenServiceOptions.RefreshTokenLifetime).Ticks.ToString());
        }
    }

    public async Task<JwtToken?> RefreshToken(JwtToken token)
    {
        var validationParameters = _jwtBearerOptions.TokenValidationParameters;
        validationParameters.ValidateLifetime = false;
        validationParameters.ValidateAudience = false;
        validationParameters.ValidIssuer = _issuer;
        validationParameters.IssuerSigningKey = _signingCredentials.Key;

        var principal = _securityTokenHandler.ValidateToken(token.Token, validationParameters, out var securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256))
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

        if (refreshTokenLifetime?.CompareTo(DateTime.UtcNow) <= 0)
        {
            await RemoveRefreshTokenAsync();

            return default;
        }

        var refreshedToken = await GenerateToken(user.Id, jwtSecurityToken.Audiences);

        await RemoveRefreshTokenAsync();

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

    public async Task RevokeRefreshTokens(string userId)
    {
        var refreshTokens = await _context.UserTokens
            .Where(token => token.UserId == userId)
            .Where(token => token.LoginProvider == _tokenServiceOptions.ApplicationLoginProvider)
            .Where(token => token.Name.StartsWith("refresh_token"))
            .ToListAsync();

        _context.RemoveRange(refreshTokens);

        await _context.SaveChangesAsync();
    }

    private static string EncodeRefreshToken(Guid refreshTokenId) => $"refresh_token:{refreshTokenId}";
}
using System.Collections;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Incremental.Common.Authentication.Jwt.Testing.Context;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Incremental.Common.Authentication.Jwt.Testing;

public class TokenServiceTests
{
    private TestingDbContext? _testingDbContext;
    private ITokenService? _tokenService;
    private IdentityUser? _testUser;
    
    private const string OptionsTokenIssuer = "https://testing.local";
    private const string OptionsTokenSecurityKey = "VerySecureSecurityKeySuchLongKeyMuchSecure";

    [SetUp]
    public async Task Setup()
    {
        var services = new ServiceCollection();

        services.AddLogging();
        
        services.AddDbContext<TestingDbContext>(builder => builder.UseInMemoryDatabase("jwt"));

        services.AddIdentity<IdentityUser, IdentityRole>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedAccount = false;
            options.Password.RequireUppercase = false;
            options.Password.RequireNonAlphanumeric = false;
            options.Password.RequireDigit = false;
            options.Password.RequiredLength = 4;
        }).AddEntityFrameworkStores<TestingDbContext>();
        
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
        
        services.AddOptions<TokenServiceOptions>().Configure(options =>
        {
            options.TokenIssuer = OptionsTokenIssuer;
            options.TokenSecurityKey = OptionsTokenSecurityKey;
        });
        
        services.AddScoped<ITokenService, TokenService<IdentityUser, TestingDbContext>>();

        var provider = services.BuildServiceProvider();

        _testingDbContext = provider.GetRequiredService<TestingDbContext>();
            
        _tokenService = provider.GetRequiredService<ITokenService>();
        
        var userManager = provider.GetRequiredService<UserManager<IdentityUser>>();
        
        await userManager.CreateAsync(new IdentityUser
        {
            Email = "testuser@testing.local",
            UserName = "testinguser"
        }, "password");

        _testUser = await userManager.FindByEmailAsync("testuser@testing.local");
        await userManager.AddClaimsAsync(_testUser, new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, _testUser.UserName),
            new Claim(ClaimTypes.NameIdentifier, _testUser.Id),
            new Claim(ClaimTypes.Email, _testUser.Email),
        });
    }

    [Test]
    public async Task TokenService_Generates_A_Token()
    {
        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);
        
        Assert.IsNotNull(token);
        Assert.IsNotNull(token);
    }
    
    [Test]
    public async Task TokenService_Generates_A_Signed_Token()
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateLifetime = false,
            ValidateAudience = false,
            ValidIssuer = OptionsTokenIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(OptionsTokenSecurityKey))
        };

        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);

        new JwtSecurityTokenHandler().ValidateToken(token.Token, validationParameters, out var securityToken);
        
        Assert.That(securityToken is JwtSecurityToken);

        Assert.AreEqual(SecurityAlgorithms.HmacSha256, (securityToken as JwtSecurityToken)!.Header.Alg);
    }
    
    [Test]
    public async Task TokenService_Generates_A_Token_With_Audience()
    {
        const string audience = "https://audience.testing.local";
        
        var validationParameters = new TokenValidationParameters
        {
            ValidateLifetime = false,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidIssuer = OptionsTokenIssuer,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(OptionsTokenSecurityKey))
        };

        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id, audience);

        new JwtSecurityTokenHandler().ValidateToken(token.Token, validationParameters, out var securityToken);

        Assert.Contains(audience, (securityToken as JwtSecurityToken)!.Audiences as ICollection);
    }
    
    [Test]
    public async Task TokenService_Generates_A_Refresh_Token()
    {
        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);
        
        Assert.IsNotNull(token.RefreshToken);
        Assert.That(token.RefreshToken != default);
    }
    
    [Test]
    public async Task TokenService_Can_Refresh_A_Token()
    {
        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);

        var refreshedToken = await _tokenService!.RefreshTokenAsync(token);
        
        Assert.IsNotNull(refreshedToken);
        Assert.IsNotEmpty(refreshedToken?.Token);
        Assert.That(token.RefreshToken != default);
    }

    [Test]
    public async Task TokenService_Can_Revoke_All_Refresh_Tokens_For_A_User()
    {
        var refreshTokensCount = await GetRefreshTokensCountAsync();
        
        Assert.NotZero(refreshTokensCount);

        await _tokenService!.RevokeRefreshTokensAsync(_testUser!.Id);

        refreshTokensCount = await GetRefreshTokensCountAsync();
        
        Assert.Zero(refreshTokensCount);

        async Task<int> GetRefreshTokensCountAsync()
        {
            return await _testingDbContext!.UserTokens
                .Where(t => t.UserId == _testUser!.Id)
                .Where(t => t.LoginProvider == new TokenServiceOptions().ApplicationLoginProvider)
                .Where(t => t.Name.StartsWith("refresh_token"))
                .CountAsync();
        }
    }
    
    [Test]
    public async Task TokenService_Will_Not_Refresh_A_Revoked_Token()
    {
        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);

        var refreshTokensCount = await GetRefreshTokensCountAsync();
        Assert.NotZero(refreshTokensCount);

        await _tokenService!.RevokeRefreshTokensAsync(_testUser!.Id);

        refreshTokensCount = await GetRefreshTokensCountAsync();
        Assert.Zero(refreshTokensCount);
        
        var refreshedToken = await _tokenService!.RefreshTokenAsync(token);
        
        Assert.IsNull(refreshedToken);

        async Task<int> GetRefreshTokensCountAsync()
        {
            return await _testingDbContext!.UserTokens
                .Where(t => t.UserId == _testUser!.Id)
                .Where(t => t.LoginProvider == new TokenServiceOptions().ApplicationLoginProvider)
                .Where(t => t.Name.StartsWith("refresh_token"))
                .CountAsync();
        }
    }
    
    [Test]
    public async Task TokenService_Retrieves_A_ClaimsPrincipal_From_A_Token()
    {
        var token = await _tokenService!.GenerateTokenAsync(_testUser!.Id);

        var principal = _tokenService.RetrieveClaimsPrincipal(token);
        
        Assert.IsInstanceOf<ClaimsPrincipal>(principal);

        Assert.IsNotEmpty(principal!.Claims);
    }

}
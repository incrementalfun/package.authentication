using System.Security.Claims;

namespace Incremental.Common.Authentication.Configuration;

/// <summary>
/// Common claims for Incremental.
/// </summary>
public struct Claims
{
    private static string ClaimFormat(string claim) => $"incremental:{claim.ToLower()}";
        
    /// <summary>
    /// Generate Scope claim.
    /// </summary>
    /// <param name="scope"></param>
    /// <returns></returns>
    public static Claim Scope(string scope) => new Claim(ClaimFormat("scope"), scope.ToLower());
}
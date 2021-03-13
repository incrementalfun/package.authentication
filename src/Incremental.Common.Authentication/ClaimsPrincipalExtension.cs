using System.Security.Claims;
using Microsoft.IdentityModel.JsonWebTokens;

namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Extension methods to simplify claims usage.
    /// </summary>
    public static class ClaimsPrincipalExtension
    {
        /// <summary>
        /// Get user id.
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetId(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(ClaimTypes.NameIdentifier);
        }
        
        /// <summary>
        /// Get user email.
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetEmail(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(ClaimTypes.Email);
        }

        /// <summary>
        /// get user username.
        /// </summary>
        /// <param name="principal"></param>
        /// <returns></returns>
        public static string GetUsername(this ClaimsPrincipal principal)
        {
            return principal.FindFirstValue(JwtRegisteredClaimNames.Sub);
        }
    }
}
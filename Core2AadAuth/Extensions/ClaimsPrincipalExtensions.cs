using System;
using System.Security.Claims;

namespace Core2AadAuth.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Gets the user's Azure AD object id
        /// </summary>
        public static string GetObjectId(this ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                throw new ArgumentNullException(nameof(principal));
            }

            return principal.FindFirstValue("http://schemas.microsoft.com/identity/claims/objectidentifier");
        }
    }
}

using System.Security.Claims;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Core2AadAuth.Services
{
    public interface ITokenCacheFactory
    {
        TokenCache CreateForUser(ClaimsPrincipal user);
    }
}
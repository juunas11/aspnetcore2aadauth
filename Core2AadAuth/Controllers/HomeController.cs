using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Core2AadAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Core2AadAuth.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private static readonly HttpClient Client = new HttpClient();
        private readonly IDistributedCache _cache;
        private readonly IConfiguration _config;

        public HomeController(IDistributedCache cache, IConfiguration config)
        {
            _cache = cache;
            _config = config;
        }

        [AllowAnonymous]
        public IActionResult Index()
        {
            return View();
        }

        public IActionResult UserClaims() => View();

        public async Task<IActionResult> MsGraph()
        {
            HttpResponseMessage res = await QueryGraphAsync("/me");

            ViewBag.GraphResponse = await res.Content.ReadAsStringAsync();
            
            return View();
        }

        public async Task<IActionResult> ProfilePhoto()
        {
            HttpResponseMessage res = await QueryGraphAsync("/me/photo/$value");

            return File(await res.Content.ReadAsStreamAsync(), "image/jpeg");
        }

        private async Task<HttpResponseMessage> QueryGraphAsync(string relativeUrl)
        {
            var req = new HttpRequestMessage(HttpMethod.Get, "https://graph.microsoft.com/beta" + relativeUrl);
            
            string accessToken = await GetAccessTokenAsync();
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

            return await Client.SendAsync(req);
        }

        private async Task<string> GetAccessTokenAsync()
        {
            string authority = _config["Authentication:Authority"];

            string userId = User.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier").Value;
            var cache = new AdalDistributedTokenCache(_cache, userId);

            var authContext = new AuthenticationContext(authority, cache);

            string clientId = _config["Authentication:ClientId"];
            string clientSecret = _config["Authentication:ClientSecret"];
            var credential = new ClientCredential(clientId, clientSecret);

            var result = await authContext.AcquireTokenSilentAsync("https://graph.microsoft.com", credential, new UserIdentifier(userId, UserIdentifierType.UniqueId));

            return result.AccessToken;
        }
    }
}

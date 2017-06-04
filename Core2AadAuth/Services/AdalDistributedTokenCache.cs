using System;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Core2AadAuth.Services
{
    public class AdalDistributedTokenCache : TokenCache
    {
        private readonly IDistributedCache _cache;
        private readonly string _userId;

        public AdalDistributedTokenCache(IDistributedCache cache, string userId)
        {
            _cache = cache;
            _userId = userId;
            BeforeAccess = BeforeAccessNotification;
            AfterAccess = AfterAccessNotification;
        }

        private string GetCacheKey()
        {
            return $"{_userId}_TokenCache";
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            Deserialize(_cache.Get(GetCacheKey()));
        }

        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            if (HasStateChanged)
            {
                _cache.Set(GetCacheKey(), Serialize(), new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1)
                });
                HasStateChanged = false;
            }
        }
    }
}
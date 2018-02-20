using System;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace Core2AadAuth.Services
{
    /// <summary>
    /// Caches access and refresh tokens for Azure AD
    /// </summary>
    public class AdalDistributedTokenCache : TokenCache
    {
        private readonly IDistributedCache _distributedCache;
        private readonly IMemoryCache _memoryCache;
        private readonly IDataProtector _dataProtector;
        private readonly string _userId;

        /// <summary>
        /// Constructs a token cache
        /// </summary>
        /// <param name="distributedCache">Distributed cache used as level 2 cache</param>
        /// <param name="memoryCache">Memory cache used as level 1 cache</param>
        /// <param name="dataProtectionProvider">The protector provider for encrypting/decrypting the cached data</param>
        /// <param name="userId">The user's unique identifier</param>
        public AdalDistributedTokenCache(IDistributedCache distributedCache, IMemoryCache memoryCache, IDataProtectionProvider dataProtectionProvider, string userId)
        {
            _distributedCache = distributedCache;
            _memoryCache = memoryCache;
            _dataProtector = dataProtectionProvider.CreateProtector("AadTokens");
            _userId = userId;
            BeforeAccess = BeforeAccessNotification;
            AfterAccess = AfterAccessNotification;
        }

        private void BeforeAccessNotification(TokenCacheNotificationArgs args)
        {
            //Called before ADAL tries to access the cache,
            //so this is where we should read from the distibruted cache
            //It sucks that ADAL's API is synchronous, so we must do a blocking call here
            byte[] cachedData = GetFromCaches();

            if (cachedData != null)
            {
                //Decrypt and deserialize the cached data
                Deserialize(_dataProtector.Unprotect(cachedData));
            }
            else
            {
                //Ensures the cache is cleared in TokenCache
                Deserialize(null);
            }
        }

        private byte[] GetFromCaches()
        {
            byte[] cachedData;
            string cacheKey = GetCacheKey();
            //Try Level 1, in-memory cache first
            if (!_memoryCache.TryGetValue(cacheKey, out cachedData))
            {
                //If that doesn't work, then try distributed cache
                cachedData = _distributedCache.Get(GetCacheKey());
                if (cachedData != null)
                {
                    //Found from L2, write to L1 for next access
                    SetToMemoryCache(cachedData);
                }
            }
            return cachedData;
        }

        private void SetToMemoryCache(byte[] data)
        {
            _memoryCache.Set(GetCacheKey(), data, TimeSpan.FromHours(8));
        }

        private void AfterAccessNotification(TokenCacheNotificationArgs args)
        {
            //Called after ADAL is done accessing the token cache
            if (HasStateChanged)
            {
                //In this case the cache state has changed, maybe a new token was written
                //So we encrypt and write the data to the distributed cache
                var data = _dataProtector.Protect(Serialize());
                //Put data to both caches, so that 1) it is available right away in-memory here
                //and 2) in L2 for other instances
                _distributedCache.Set(GetCacheKey(), data, new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = TimeSpan.FromDays(1)
                });
                SetToMemoryCache(data);
                HasStateChanged = false;
            }
        }

        private string GetCacheKey()
        {
            return $"{_userId}_TokenCache";
        }
    }
}
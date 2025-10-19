namespace Azure.Security
{
    using System;

#if NET9_0
    using Microsoft.Extensions.Caching.Memory;
#else
    using System.Runtime.Caching;
#endif

    public class Cache
    {
#if NET9_0
        private readonly IMemoryCache _dataCache;

        public Cache(IMemoryCache memoryCache)
        {
            _dataCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
        }

        public void AddItem<T>(string key, T value)
        {
            var options = new MemoryCacheEntryOptions
            {
                SlidingExpiration = TimeSpan.FromHours(3)
            };
            _dataCache.Set(key, value, options);
        }

        public void AddItem<T>(string key, T value, int cacheMins)
        {
            var options = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(cacheMins)
            };
            _dataCache.Set(key, value, options);
        }

        public T? GetItem<T>(string key)
        {
            // TryGetValue is a safer way to get items in the modern API.
            _dataCache.TryGetValue(key, out T? value);
            return value;
        }

        public void RemoveItem(string key)
        {
            _dataCache.Remove(key);
        }

#else
        public static Cache Current => new Cache();

        // Cache
        private readonly MemoryCache _dataCache;
        public CacheItemPolicy CachePolicy { get; set; }

        public Cache()
        {
            // Initialise the cache provider and get the default cache container
            _dataCache = MemoryCache.Default;

            // Set up a default item policy
            CachePolicy = new CacheItemPolicy
            {
                SlidingExpiration = TimeSpan.FromHours(3)
            };
        }

        /// <summary>
        /// Add the specified object to the cache
        /// </summary>
        public void AddItem<T>(string key, T value)
        {
            // Add the item straight into the cache
            _dataCache.Set(key, value, CachePolicy);
        }

        /// <summary>
        /// Add the specified object to the cache for the specified amount of minutes
        /// </summary>
        public void AddItem<T>(string key, T value, int cacheMins)
        {
            // Create a cache policy
            var itemCachePolicy = new CacheItemPolicy()
            {
                AbsoluteExpiration = DateTime.Now + TimeSpan.FromMinutes(cacheMins)
            };

            // Add the item straight into the cache
            _dataCache.Set(key, value, itemCachePolicy);
        }

        /// <summary>
        /// Get an item from the cache
        /// </summary>
        /// <returns>Returns null if item does not exist</returns>
        public T GetItem<T>(string key)
        {
            // Try to get the object from the cache
            var obj = _dataCache.Get(key);

            // Return the item or null
            if (obj != null)
                return (T)(obj);
            
            return default;
        }

        /// <summary>
        /// Remove an item from the cache
        /// </summary>
        public void RemoveItem(string key)
        {
            // Try to remove the object from the cache;
            _dataCache.Remove(key);
        }
#endif
    }
}

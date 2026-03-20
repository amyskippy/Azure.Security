using System;
using Microsoft.Extensions.Caching.Memory;

namespace Azure.Security;

public static class CacheExtensions
{
    public static void AddItem<T>(this IMemoryCache cache, string key, T value)
    {
        var options = new MemoryCacheEntryOptions
        {
            SlidingExpiration = TimeSpan.FromHours(3)
        };
        cache.Set(key, value, options);
    }

    public static void AddItem<T>(this IMemoryCache cache, string key, T value, int cacheMins)
    {
        var options = new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(cacheMins)
        };
        cache.Set(key, value, options);
    }

    public static T? GetItem<T>(this IMemoryCache cache, string key)
    {
        // TryGetValue is a safer way to get items in the modern API.
        cache.TryGetValue(key, out T? value);
        return value;
    }

    public static void RemoveItem(this IMemoryCache cache, string key)
    {
        cache.Remove(key);
    }
}
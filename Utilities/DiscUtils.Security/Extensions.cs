using System.Collections.Generic;

namespace DiscUtils.Security
{
    internal static class Extensions
    {
        public static TValue GetValueOrDefault<TKey, TValue>(this IReadOnlyDictionary<TKey, TValue> dictionary,
                                                             TKey key,
                                                             TValue defaultValue)
        {
            return dictionary.TryGetValue(key, out TValue value) ? value : defaultValue;
        }
    }
}

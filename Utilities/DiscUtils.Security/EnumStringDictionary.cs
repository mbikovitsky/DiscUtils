using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace DiscUtils.Security
{
    internal class EnumStringDictionary : IReadOnlyDictionary<Enum, string>, IReadOnlyDictionary<string, Enum>
    {
        private readonly IReadOnlyDictionary<Enum, string> _enumToString;
        private readonly IReadOnlyDictionary<string, Enum> _stringToEnum;

        public EnumStringDictionary(IEnumerable<KeyValuePair<Enum, string>> pairs)
        {
            Dictionary<Enum, string> enumToString = new Dictionary<Enum, string>();
            Dictionary<string, Enum> stringToEnum = new Dictionary<string, Enum>();

            foreach (KeyValuePair<Enum, string> pair in pairs)
            {
                enumToString[pair.Key] = pair.Value;
                stringToEnum[pair.Value] = pair.Key;
            }

            _enumToString = enumToString;
            _stringToEnum = stringToEnum;
        }

        public EnumStringDictionary(IEnumerable<KeyValuePair<string, Enum>> pairs) :
            this(pairs.Select(pair => new KeyValuePair<Enum, string>(pair.Value, pair.Key)))
        {
        }

        public IEnumerator<KeyValuePair<Enum, string>> GetEnumerator()
        {
            return _enumToString.GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            return ((IEnumerable)_enumToString).GetEnumerator();
        }

        public int Count => _enumToString.Count;

        public bool ContainsKey(Enum key)
        {
            return _enumToString.ContainsKey(key);
        }

        public bool TryGetValue(Enum key, out string value)
        {
            return _enumToString.TryGetValue(key, out value);
        }

        public string this[Enum key] => _enumToString[key];

        public IEnumerable<Enum> Keys => _enumToString.Keys;

        public IEnumerable<string> Values => _enumToString.Values;

        IEnumerator<KeyValuePair<string, Enum>> IEnumerable<KeyValuePair<string, Enum>>.GetEnumerator()
        {
            return _stringToEnum.GetEnumerator();
        }

        public bool ContainsKey(string key)
        {
            return _stringToEnum.ContainsKey(key);
        }

        public bool TryGetValue(string key, out Enum value)
        {
            return _stringToEnum.TryGetValue(key, out value);
        }

        public Enum this[string key] => _stringToEnum[key];

        IEnumerable<string> IReadOnlyDictionary<string, Enum>.Keys => _stringToEnum.Keys;

        IEnumerable<Enum> IReadOnlyDictionary<string, Enum>.Values => _stringToEnum.Values;
    }
}
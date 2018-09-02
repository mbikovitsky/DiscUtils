using System;
using System.Collections;

namespace DiscUtils.Security.AccessControl
{
    public sealed class AceEnumerator : IEnumerator
    {
        #region Private Members

        //
        // Current enumeration index
        //

        private int _current;

        //
        // Parent collection
        //

        private readonly GenericAcl _acl;

        #endregion

        #region Constructors

        internal AceEnumerator(GenericAcl collection)
        {
            if (collection == null)
            {
                throw new ArgumentNullException(nameof(collection));
            }

            _acl = collection;
            Reset();
        }

        #endregion

        #region IEnumerator Interface

        object IEnumerator.Current
        {
            get
            {
                if (_current == -1 ||
                    _current >= _acl.Count)
                {
                    throw new InvalidOperationException(SR.Arg_InvalidOperationException);
                }

                return _acl[_current];
            }
        }

        public GenericAce Current
        {
            get { return ((IEnumerator)this).Current as GenericAce; }
        }

        public bool MoveNext()
        {
            _current++;

            return (_current < _acl.Count);
        }

        public void Reset()
        {
            _current = -1;
        }

        #endregion
    }
}

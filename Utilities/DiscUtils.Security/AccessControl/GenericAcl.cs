using System;
using System.Collections;
using System.Linq;

namespace DiscUtils.Security.AccessControl
{
    public abstract class GenericAcl : ICollection
    {
        #region Constructors

        protected GenericAcl()
        { }

        #endregion

        #region Public Constants

        //
        // ACL revisions
        //

        public static readonly byte AclRevision = 2;
        public static readonly byte AclRevisionDS = 4;

        //
        // Maximum length of a binary representation of the ACL
        //

        public static readonly int MaxBinaryLength = ushort.MaxValue;

        #endregion

        #region Protected Members

        //
        //  Define an ACL and the ACE format.  The structure of an ACL header
        //  followed by one or more ACEs.  Pictorally the structure of an ACL header
        //  is as follows:
        //
        //       3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
        //       1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
        //      +-------------------------------+---------------+---------------+
        //      |            AclSize            |      Sbz1     |  AclRevision  |
        //      +-------------------------------+---------------+---------------+
        //      |              Sbz2             |           AceCount            |
        //      +-------------------------------+-------------------------------+
        //

        internal const int HeaderLength = 8;

        #endregion

        #region Public Properties

        //
        // Returns the revision of the ACL
        //

        public abstract byte Revision { get; }

        //
        // Returns the length of the binary representation of the ACL
        //

        public abstract int BinaryLength { get; }

        //
        // Retrieves the ACE at a specified index
        //

        public abstract GenericAce this[int index] { get; set; }

        #endregion

        #region Public Methods

        //
        // Returns the binary representation of the ACL
        //

        public abstract void GetBinaryForm(byte[] binaryForm, int offset);

        public string GetSddlForm()
        {
            return string.Join("", this.Cast<GenericAce>().Select(ace => $"({ace.GetSddlForm()})"));
        }

        #endregion

        #region ICollection Implementation

        void ICollection.CopyTo(Array array, int index)
        {
            if (array == null)
            {
                throw new ArgumentNullException(nameof(array));
            }

            if (array.Rank != 1)
            {
                throw new RankException("Only single dimension arrays are supported here.");
            }

            if (index < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(index),
                    "Non-negative number required.");
            }
            else if (array.Length - index < Count)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(array),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }

            for (int i = 0; i < Count; i++)
            {
                array.SetValue(this[i], index + i);
            }
        }

        public void CopyTo(GenericAce[] array, int index)
        {
            ((ICollection)this).CopyTo(array, index);
        }

        public abstract int Count { get; }

        public bool IsSynchronized
        {
            get { return false; }
        }

        public virtual object SyncRoot
        {
            get { return this; }
        }

        #endregion

        #region IEnumerable Implementation

        IEnumerator IEnumerable.GetEnumerator()
        {
            return new AceEnumerator(this);
        }

        public AceEnumerator GetEnumerator()
        {
            return ((IEnumerable)this).GetEnumerator() as AceEnumerator;
        }

        #endregion
    }
}

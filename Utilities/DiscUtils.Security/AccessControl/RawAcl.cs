using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;

namespace DiscUtils.Security.AccessControl
{
    public sealed class RawAcl : GenericAcl
    {
        #region Private Members

        private byte _revision;
        private List<GenericAce> _aces;

        #endregion

        #region Private Methods

        private static void VerifyHeader(byte[] binaryForm, int offset, out byte revision, out int count, out int length)
        {
            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }

            if (offset < 0)
            {
                //
                // Offset must not be negative
                //

                throw new ArgumentOutOfRangeException(
                    nameof(offset),
                    "Non-negative number required.");
            }

            if (binaryForm.Length - offset < HeaderLength)
            {
                //
                // We expect at least the ACL header
                //

                goto InvalidParameter;
            }

            revision = binaryForm[offset + 0];
            length = (binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8);
            count = (binaryForm[offset + 4] << 0) + (binaryForm[offset + 5] << 8);

            if (length > binaryForm.Length - offset)
            {
                //
                // Reported length of ACL ought to be no longer than the
                // length of the buffer passed in
                //

                goto InvalidParameter;
            }

            return;

            InvalidParameter:

            throw new ArgumentOutOfRangeException(
                nameof(binaryForm),
                "Destination array is not long enough to copy all the required data. Check array length and offset.");
        }

        private void MarshalHeader(byte[] binaryForm, int offset)
        {
            if (binaryForm == null)
            {
                throw new ArgumentNullException(nameof(binaryForm));
            }
            else if (offset < 0)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(offset),
                    "Non-negative number required.");
            }
            else if (BinaryLength > MaxBinaryLength)
            {
                throw new InvalidOperationException("Length of the access control list exceed the allowed maximum.");
            }
            else if (binaryForm.Length - offset < BinaryLength)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }

            binaryForm[offset + 0] = Revision;
            binaryForm[offset + 1] = 0;
            binaryForm[offset + 2] = unchecked((byte)(BinaryLength >> 0));
            binaryForm[offset + 3] = (byte)(BinaryLength >> 8);
            binaryForm[offset + 4] = unchecked((byte)(Count >> 0));
            binaryForm[offset + 5] = (byte)(Count >> 8);
            binaryForm[offset + 6] = 0;
            binaryForm[offset + 7] = 0;
        }

        internal void SetBinaryForm(byte[] binaryForm, int offset)
        {
            int count, length;

            //
            // Verify the header and extract interesting header info
            //

            VerifyHeader(binaryForm, offset, out _revision, out count, out length);

            //
            // Remember how far ahead the binary form should end (for later verification)
            //

            length += offset;

            offset += HeaderLength;

            _aces = new List<GenericAce>(count);
            int binaryLength = HeaderLength;

            for (int i = 0; i < count; i++)
            {
                GenericAce ace = GenericAce.CreateFromBinaryForm(binaryForm, offset);

                int aceLength = ace.BinaryLength;

                if (binaryLength + aceLength > MaxBinaryLength)
                {
                    //
                    // The ACE was too long - it would overflow the ACL maximum length
                    //

                    throw new ArgumentException(
                        "The binary form of an ACL object is invalid.",
                        nameof(binaryForm));
                }

                _aces.Add(ace);

                if (aceLength % 4 != 0)
                {
                    //
                    // This indicates a bug in one of the ACE classes.
                    // Binary length of an ace must ALWAYS be divisible by 4.
                    //

                    Debug.Assert(false, "aceLength % 4 != 0");
                    // Replacing SystemException with InvalidOperationException. This code path 
                    // indicates a bad ACE, but I don't know of a great exception to represent that. 
                    // InvalidOperation seems to be the closest, though it's definitely not exactly 
                    // right for this scenario.
                    throw new InvalidOperationException();
                }

                binaryLength += aceLength;

                if (_revision == AclRevisionDS)
                {
                    //
                    // Increment the offset by the advertised length rather than the 
                    // actual binary length. (Ideally these two should match, but for
                    // object aces created through ADSI, the actual length is 32 bytes 
                    // less than the allocated size of the ACE. This is a bug in ADSI.)
                    //
                    offset += (binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8);
                }
                else
                {
                    offset += aceLength;
                }

                //
                // Verify that no more than the advertised length of the ACL was consumed
                //

                if (offset > length)
                {
                    goto InvalidParameter;
                }
            }

            return;

            InvalidParameter:

            throw new ArgumentException(
                "The binary form of an ACL object is invalid.",
                nameof(binaryForm));
        }

        #endregion

        #region Constructors

        //
        // Creates an empty ACL
        //

        public RawAcl(byte revision, int capacity)
            : base()
        {
            _revision = revision;
            _aces = new List<GenericAce>(capacity);
        }

        //
        // Creates an ACL from its binary representation
        //

        public RawAcl(byte[] binaryForm, int offset)
            : base()
        {
            SetBinaryForm(binaryForm, offset);
        }

        /// <summary>
        /// Creates an ACL from its SDDL representation.
        /// </summary>
        /// <param name="sddlForm"></param>
        public RawAcl(string sddlForm)
        {
            Match match = Regex.Match(sddlForm, @"^(?:\((?<ace>.+?)\))+$");
            if (!match.Success)
            {
                throw new ArgumentException(
                    "The SDDL form of an ACL object is invalid.",
                    nameof(sddlForm));
            }

            _aces = new List<GenericAce>(match.Groups["ace"].Captures.Count);
            int binaryLength = HeaderLength;

            foreach (string aceString in match.Groups["ace"].Captures.Cast<Capture>().Select(capture => capture.Value))
            {
                GenericAce ace = GenericAce.CreateFromSddl(aceString);

                int aceLength = ace.BinaryLength;

                if (binaryLength + aceLength > MaxBinaryLength)
                {
                    //
                    // The ACE was too long - it would overflow the ACL maximum length
                    //

                    throw new ArgumentException(
                        "The SDDL form of an ACL object is invalid.",
                        nameof(sddlForm));
                }

                _aces.Add(ace);

                if (aceLength % 4 != 0)
                {
                    //
                    // This indicates a bug in one of the ACE classes.
                    // Binary length of an ace must ALWAYS be divisible by 4.
                    //

                    Debug.Assert(false, "aceLength % 4 != 0");
                    // Replacing SystemException with InvalidOperationException. This code path 
                    // indicates a bad ACE, but I don't know of a great exception to represent that. 
                    // InvalidOperation seems to be the closest, though it's definitely not exactly 
                    // right for this scenario.
                    throw new InvalidOperationException();
                }

                binaryLength += aceLength;
            }

            _revision = AclRevision;
        }

        #endregion

        #region Public Properties

        //
        // Returns the revision of the ACL
        //

        public override byte Revision
        {
            get { return _revision; }
        }

        //
        // Returns the number of ACEs in the ACL
        //

        public override int Count
        {
            get { return _aces.Count; }
        }

        //
        // Returns the length of the binary representation of the ACL
        //

        public override int BinaryLength
        {
            get
            {
                int binaryLength = HeaderLength;

                for (int i = 0; i < Count; i++)
                {
                    GenericAce ace = _aces[i];
                    binaryLength += ace.BinaryLength;
                }

                return binaryLength;
            }
        }

        #endregion

        #region Public Methods

        //
        // Returns the binary representation of the ACL
        //

        public override void GetBinaryForm(byte[] binaryForm, int offset)
        {
            //
            // Populate the header
            //

            MarshalHeader(binaryForm, offset);
            offset += HeaderLength;

            for (int i = 0; i < Count; i++)
            {
                GenericAce ace = _aces[i];

                ace.GetBinaryForm(binaryForm, offset);

                int aceLength = ace.BinaryLength;

                if (aceLength % 4 != 0)
                {
                    //
                    // This indicates a bug in one of the ACE classes.
                    // Binary length of an ace must ALWAYS be divisible by 4.
                    //

                    Debug.Assert(false, "aceLength % 4 != 0");
                    // Replacing SystemException with InvalidOperationException. This code path 
                    // indicates a bad ACE, but I don't know of a great exception to represent that. 
                    // InvalidOperation seems to be the closest, though it's definitely not exactly 
                    // right for this scenario.
                    throw new InvalidOperationException();
                }

                offset += aceLength;
            }
        }

        //
        // Return an ACE at a particular index
        // The ACE is not cloned prior to returning, enabling the caller
        // to modify the ACE in place (a potentially dangerous operation)
        //

        public override GenericAce this[int index]
        {
            get
            {
                return _aces[index];
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                if (value.BinaryLength % 4 != 0)
                {
                    //
                    // This indicates a bug in one of the ACE classes.
                    // Binary length of an ace must ALWAYS be divisible by 4.
                    //

                    Debug.Assert(false, "aceLength % 4 != 0");
                    // Replacing SystemException with InvalidOperationException. This code path 
                    // indicates a bad ACE, but I don't know of a great exception to represent that. 
                    // InvalidOperation seems to be the closest, though it's definitely not exactly 
                    // right for this scenario.
                    throw new InvalidOperationException();
                }

                int newBinaryLength = BinaryLength - (index < _aces.Count ? _aces[index].BinaryLength : 0) + value.BinaryLength;

                if (newBinaryLength > MaxBinaryLength)
                {
                    throw new OverflowException("Length of the access control list exceed the allowed maximum.");
                }

                _aces[index] = value;
            }
        }

        //
        // Adds an ACE at the specified index
        //

        public void InsertAce(int index, GenericAce ace)
        {
            if (ace == null)
            {
                throw new ArgumentNullException(nameof(ace));
            }

            if (BinaryLength + ace.BinaryLength > MaxBinaryLength)
            {
                throw new OverflowException("Length of the access control list exceed the allowed maximum.");
            }

            _aces.Insert(index, ace);
        }

        //
        // Removes an ACE at the specified index
        //

        public void RemoveAce(int index)
        {
            GenericAce ace = _aces[index];
            _aces.RemoveAt(index);
        }

        #endregion
    }
}

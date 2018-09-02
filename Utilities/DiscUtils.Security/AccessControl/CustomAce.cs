using System;
using System.Diagnostics;

namespace DiscUtils.Security.AccessControl
{
    /// <summary>
    /// User-defined ACEs are ACE types we don't recognize.
    /// They contain a standard ACE header followed by a binary blob.
    /// </summary>
    public sealed class CustomAce : GenericAce
    {
        #region Private Members

        //
        // Opaque data is what follows the ACE header.
        // It is not interpreted by any code except that which
        // understands the ACE type.
        //

        private byte[] _opaque;

        #endregion

        #region Public Constants

        //
        // Returns the maximum allowed length of opaque data
        //

        public static readonly int MaxOpaqueLength = ushort.MaxValue - HeaderLength;

        #endregion

        #region Constructors

        public CustomAce(AceType type, AceFlags flags, byte[] opaque)
            : base(type, flags)
        {
            if (type <= AceType.MaxDefinedAceType)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(type),
                    "User-defined ACEs must not have a well-known ACE type.");
            }

            SetOpaque(opaque);
        }

        #endregion

        #region Public Properties

        //
        // Returns the length of the opaque blob
        //

        public int OpaqueLength
        {
            get
            {
                if (_opaque == null)
                {
                    return 0;
                }
                else
                {
                    return _opaque.Length;
                }
            }
        }

        //
        // Returns the length of the binary representation of this ACE
        // The value returned is really an unsigned short
        //

        public /* sealed */ override int BinaryLength
        {
            get
            {
                return HeaderLength + OpaqueLength;
            }
        }

        #endregion

        #region Public Methods

        //
        // Methods to set and retrieve the opaque portion of the ACE
        // Important: the caller is given the actual (not cloned) copy of the data
        //

        public byte[] GetOpaque()
        {
            return _opaque;
        }

        public void SetOpaque(byte[] opaque)
        {
            if (opaque != null)
            {
                if (opaque.Length > MaxOpaqueLength)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(opaque),
                        $"The length of the array must be between {0} and {MaxOpaqueLength}, inclusive.");
                }
                else if (opaque.Length % 4 != 0)
                {
                    throw new ArgumentOutOfRangeException(
                        nameof(opaque),
                        $"The length of the array must be a multiple of {4}.");
                }
            }

            _opaque = opaque;
        }

        //
        // Copies the binary representation of the ACE into a given array
        // starting at the given offset.
        //

        public /* sealed */ override void GetBinaryForm(byte[] binaryForm, int offset)
        {
            //
            // Populate the header
            //

            MarshalHeader(binaryForm, offset);
            offset += HeaderLength;

            //
            // Header is followed by the opaque data
            //

            if (OpaqueLength != 0)
            {
                if (OpaqueLength > MaxOpaqueLength)
                {
                    Debug.Assert(false, "OpaqueLength somehow managed to exceed MaxOpaqueLength");
                    // Replacing SystemException with InvalidOperationException. It's not a perfect fit,
                    // but it's the best exception type available to indicate a failure because
                    // of a bug in the ACE itself.
                    throw new InvalidOperationException();
                }

                GetOpaque().CopyTo(binaryForm, offset);
            }
        }

        public override string GetSddlForm()
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}

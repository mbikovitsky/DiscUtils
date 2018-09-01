using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public sealed class CompoundAce : KnownAce
    {
        #region Private Members

        private CompoundAceType _compoundAceType;

        #endregion

        #region Private Constants

        private const int AceTypeLength = 4; // including 2 reserved bytes

        #endregion

        #region Constructors

        public CompoundAce(AceFlags flags, int accessMask, CompoundAceType compoundAceType, SecurityIdentifier sid)
            : base(AceType.AccessAllowedCompound, flags, accessMask, sid)
        {
            //
            // The compound ACE type value is deliberately not validated
            //

            _compoundAceType = compoundAceType;
        }

        #endregion

        #region Static Parser

        internal static bool ParseBinaryForm(
            byte[] binaryForm,
            int offset,
            out int accessMask,
            out CompoundAceType compoundAceType,
            out SecurityIdentifier sid)
        {
            //
            // Verify the ACE header
            //

            VerifyHeader(binaryForm, offset);

            //
            // Verify the length field
            //

            if (binaryForm.Length - offset < HeaderLength + AccessMaskLength + AceTypeLength + SecurityIdentifier.MinBinaryLength)
            {
                goto InvalidParameter;
            }

            int baseOffset = offset + HeaderLength;
            int offsetLocal = 0;

            //
            // The access mask is stored in big-endian format
            //

            accessMask =
                unchecked((int)(
                (((uint)binaryForm[baseOffset + 0]) << 0) +
                (((uint)binaryForm[baseOffset + 1]) << 8) +
                (((uint)binaryForm[baseOffset + 2]) << 16) +
                (((uint)binaryForm[baseOffset + 3]) << 24)));

            offsetLocal += AccessMaskLength;

            compoundAceType =
                (CompoundAceType)(
                (((uint)binaryForm[baseOffset + offsetLocal + 0]) << 0) +
                (((uint)binaryForm[baseOffset + offsetLocal + 1]) << 8));

            offsetLocal += AceTypeLength; // Skipping over the two reserved bits

            //
            // The access mask is followed by the SID
            //

            sid = new SecurityIdentifier(binaryForm, baseOffset + offsetLocal);

            return true;

            InvalidParameter:

            accessMask = 0;
            compoundAceType = 0;
            sid = null;

            return false;
        }

        #endregion

        #region Public Properties

        public CompoundAceType CompoundAceType
        {
            get
            {
                return _compoundAceType;
            }

            set
            {
                _compoundAceType = value;
            }
        }

        public override int BinaryLength
        {
            get
            {
                return (HeaderLength + AccessMaskLength + AceTypeLength + SecurityIdentifier.BinaryLength);
            }
        }

        #endregion

        #region Public Methods

        //
        // Copies the binary representation of the ACE into a given array
        // starting at the given offset.
        //

        public override void GetBinaryForm(byte[] binaryForm, int offset)
        {
            //
            // Populate the header
            //

            MarshalHeader(binaryForm, offset);

            int baseOffset = offset + HeaderLength;
            int offsetLocal = 0;

            //
            // Store the access mask in the big-endian format
            //
            unchecked
            {
                binaryForm[baseOffset + 0] = (byte)(AccessMask >> 0);
                binaryForm[baseOffset + 1] = (byte)(AccessMask >> 8);
                binaryForm[baseOffset + 2] = (byte)(AccessMask >> 16);
                binaryForm[baseOffset + 3] = (byte)(AccessMask >> 24);
            }

            offsetLocal += AccessMaskLength;

            //
            // Store the compound ace type and the two reserved bytes
            //

            binaryForm[baseOffset + offsetLocal + 0] = (byte)((ushort)CompoundAceType >> 0);
            binaryForm[baseOffset + offsetLocal + 1] = (byte)((ushort)CompoundAceType >> 8);
            binaryForm[baseOffset + offsetLocal + 2] = 0;
            binaryForm[baseOffset + offsetLocal + 3] = 0;

            offsetLocal += AceTypeLength;

            //
            // Store the SID
            //

            SecurityIdentifier.GetBinaryForm(binaryForm, baseOffset + offsetLocal);
        }
        #endregion
    }
}

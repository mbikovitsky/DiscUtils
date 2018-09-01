using System;
using System.Diagnostics;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public sealed class CommonAce : QualifiedAce
    {
        #region Constructors

        //
        // The constructor computes the type of this ACE and passes the rest
        // to the base class constructor
        //

        public CommonAce(AceFlags flags, AceQualifier qualifier, int accessMask, SecurityIdentifier sid, bool isCallback, byte[] opaque)
            : base(TypeFromQualifier(isCallback, qualifier), flags, accessMask, sid, opaque)
        {
        }

        #endregion

        #region Private Static Methods

        //
        // Based on the is-callback and qualifier information,
        // computes the numerical type of the ACE
        //

        private static AceType TypeFromQualifier(bool isCallback, AceQualifier qualifier)
        {
            //
            // Might benefit from replacing this with a static hard-coded table
            //

            switch (qualifier)
            {
                case AceQualifier.AccessAllowed:
                    return isCallback ? AceType.AccessAllowedCallback : AceType.AccessAllowed;

                case AceQualifier.AccessDenied:
                    return isCallback ? AceType.AccessDeniedCallback : AceType.AccessDenied;

                case AceQualifier.SystemAudit:
                    return isCallback ? AceType.SystemAuditCallback : AceType.SystemAudit;

                case AceQualifier.SystemAlarm:
                    return isCallback ? AceType.SystemAlarmCallback : AceType.SystemAlarm;

                default:

                    throw new ArgumentOutOfRangeException(
                        nameof(qualifier),
                        "Enum value was out of legal range.");
            }
        }

        #endregion

        #region Static Parser

        //
        // Called by GenericAce.CreateFromBinaryForm to parse the binary
        // form of the common ACE and extract the useful pieces.
        //

        internal static bool ParseBinaryForm(
            byte[] binaryForm,
            int offset,
            out AceQualifier qualifier,
            out int accessMask,
            out SecurityIdentifier sid,
            out bool isCallback,
            out byte[] opaque)
        {
            //
            // Verify the ACE header
            //

            VerifyHeader(binaryForm, offset);

            //
            // Verify the length field
            //

            if (binaryForm.Length - offset < HeaderLength + AccessMaskLength + SecurityIdentifier.MinBinaryLength)
            {
                goto InvalidParameter;
            }

            //
            // Identify callback ACE types
            //

            AceType type = (AceType)binaryForm[offset];

            if (type == AceType.AccessAllowed ||
                type == AceType.AccessDenied ||
                type == AceType.SystemAudit ||
                type == AceType.SystemAlarm)
            {
                isCallback = false;
            }
            else if (type == AceType.AccessAllowedCallback ||
                type == AceType.AccessDeniedCallback ||
                type == AceType.SystemAuditCallback ||
                type == AceType.SystemAlarmCallback)
            {
                isCallback = true;
            }
            else
            {
                goto InvalidParameter;
            }

            //
            // Compute the qualifier from the ACE type
            //

            if (type == AceType.AccessAllowed ||
                type == AceType.AccessAllowedCallback)
            {
                qualifier = AceQualifier.AccessAllowed;
            }
            else if (type == AceType.AccessDenied ||
                type == AceType.AccessDeniedCallback)
            {
                qualifier = AceQualifier.AccessDenied;
            }
            else if (type == AceType.SystemAudit ||
                type == AceType.SystemAuditCallback)
            {
                qualifier = AceQualifier.SystemAudit;
            }
            else if (type == AceType.SystemAlarm ||
                type == AceType.SystemAlarmCallback)
            {
                qualifier = AceQualifier.SystemAlarm;
            }
            else
            {
                goto InvalidParameter;
            }

            int baseOffset = offset + HeaderLength;
            int offsetLocal = 0;

            //
            // The access mask is stored in big-endian format
            //

            accessMask =
                (int)(
                (((uint)binaryForm[baseOffset + 0]) << 0) +
                (((uint)binaryForm[baseOffset + 1]) << 8) +
                (((uint)binaryForm[baseOffset + 2]) << 16) +
                (((uint)binaryForm[baseOffset + 3]) << 24));

            offsetLocal += AccessMaskLength;

            //
            // The access mask is followed by the SID
            //

            sid = new SecurityIdentifier(binaryForm, baseOffset + offsetLocal);

            //
            // The rest of the blob is occupied by opaque callback data, if such is supported
            //

            opaque = null;

            int aceLength = (binaryForm[offset + 3] << 8) + (binaryForm[offset + 2] << 0);

            if (aceLength % 4 != 0)
            {
                goto InvalidParameter;
            }

            int opaqueLength = aceLength - HeaderLength - AccessMaskLength - (byte)sid.BinaryLength;

            if (opaqueLength > 0)
            {
                opaque = new byte[opaqueLength];

                for (int i = 0; i < opaqueLength; i++)
                {
                    opaque[i] = binaryForm[offset + aceLength - opaqueLength + i];
                }
            }

            return true;

            InvalidParameter:

            qualifier = 0;
            accessMask = 0;
            sid = null;
            isCallback = false;
            opaque = null;

            return false;
        }

        #endregion

        #region Public Properties

        public /* sealed */ override int BinaryLength
        {
            get
            {
                return (HeaderLength + AccessMaskLength + SecurityIdentifier.BinaryLength + OpaqueLength);
            }
        }

        public static int MaxOpaqueLength(bool isCallback)
        {
            return ushort.MaxValue - HeaderLength - AccessMaskLength - SecurityIdentifier.MaxBinaryLength;
        }

        internal override int MaxOpaqueLengthInternal
        {
            get { return MaxOpaqueLength(IsCallback); }
        }

        #endregion

        #region Public Methods

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
            // Store the SID
            //

            SecurityIdentifier.GetBinaryForm(binaryForm, baseOffset + offsetLocal);
            offsetLocal += SecurityIdentifier.BinaryLength;

            //
            // Finally, if opaque is supported, store it
            //

            if (GetOpaque() != null)
            {
                if (OpaqueLength > MaxOpaqueLengthInternal)
                {
                    Debug.Assert(false, "OpaqueLength somehow managed to exceed MaxOpaqueLength");
                    // Replacing SystemException with InvalidOperationException. It's not a perfect fit,
                    // but it's the best exception type available to indicate a failure because
                    // of a bug in the ACE itself.
                    throw new InvalidOperationException();
                }

                GetOpaque().CopyTo(binaryForm, baseOffset + offsetLocal);
            }
        }
        #endregion
    }
}

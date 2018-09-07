using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class GenericAce
    {
        #region Private Members

        //
        // The 'byte' type is used to accommodate user-defined,
        // as well as well-known ACE types.
        //

        private readonly AceType _type;
        private AceFlags _flags;
        internal ushort _indexInAcl;
        #endregion

        #region Internal Constants

        //
        // Length of the ACE header in binary form
        //

        internal const int HeaderLength = 4;

        #endregion

        #region Internal Methods

        //
        // Format of the ACE header from ntseapi.h
        //
        // typedef struct _ACE_HEADER {
        //     UCHAR AceType;
        //     UCHAR AceFlags;
        //     USHORT AceSize;
        // } ACE_HEADER;
        //

        //
        // Marshal the ACE header into the given array starting at the given offset
        //

        internal void MarshalHeader(byte[] binaryForm, int offset)
        {
            int Length = BinaryLength; // Invokes the most derived property

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
            else if (binaryForm.Length - offset < BinaryLength)
            {
                //
                // The buffer will not fit the header
                //

                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }
            else if (Length > ushort.MaxValue)
            {
                //
                // Only have two bytes to store the length in.
                // Indicates a bug in the implementation, not in user's code.
                //

                Debug.Assert(false, "Length > ushort.MaxValue");
                // Replacing SystemException with InvalidOperationException. It's not a perfect fit,
                // but it's the best exception type available to indicate a failure because
                // of a bug in the ACE itself.
                throw new InvalidOperationException();
            }

            binaryForm[offset + 0] = (byte)AceType;
            binaryForm[offset + 1] = (byte)AceFlags;
            binaryForm[offset + 2] = unchecked((byte)(Length >> 0));
            binaryForm[offset + 3] = (byte)(Length >> 8);
        }

        #endregion

        #region Constructors

        internal GenericAce(AceType type, AceFlags flags)
        {
            //
            // Store the values passed in;
            // do not make any checks - anything is valid here
            //

            _type = type;
            _flags = flags;
        }

        #endregion

        #region Static Methods

        //
        // These mapper routines convert audit type flags to ACE flags and vice versa
        //

        internal static AceFlags AceFlagsFromAuditFlags(AuditFlags auditFlags)
        {
            AceFlags flags = AceFlags.None;

            if ((auditFlags & AuditFlags.Success) != 0)
            {
                flags |= AceFlags.SuccessfulAccess;
            }

            if ((auditFlags & AuditFlags.Failure) != 0)
            {
                flags |= AceFlags.FailedAccess;
            }

            if (flags == AceFlags.None)
            {
                throw new ArgumentException(
                    "Must set at least one flag.",
                    nameof(auditFlags));
            }

            return flags;
        }

        //
        // These mapper routines convert inheritance type flags to ACE flags and vice versa
        //

        internal static AceFlags AceFlagsFromInheritanceFlags(InheritanceFlags inheritanceFlags, PropagationFlags propagationFlags)
        {
            AceFlags flags = AceFlags.None;

            if ((inheritanceFlags & InheritanceFlags.ContainerInherit) != 0)
            {
                flags |= AceFlags.ContainerInherit;
            }

            if ((inheritanceFlags & InheritanceFlags.ObjectInherit) != 0)
            {
                flags |= AceFlags.ObjectInherit;
            }

            //
            // Propagation flags are meaningless without inheritance flags
            //

            if (flags != 0)
            {
                if ((propagationFlags & PropagationFlags.NoPropagateInherit) != 0)
                {
                    flags |= AceFlags.NoPropagateInherit;
                }

                if ((propagationFlags & PropagationFlags.InheritOnly) != 0)
                {
                    flags |= AceFlags.InheritOnly; // ContainerInherit already turned on above
                }
            }

            return flags;
        }

        //
        // Sanity-check the ACE header (used by the unmarshaling logic)
        //

        internal static void VerifyHeader(byte[] binaryForm, int offset)
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
            else if (binaryForm.Length - offset < HeaderLength)
            {
                //
                // We expect at least the ACE header ( 4 bytes )
                //

                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }
            else if ((binaryForm[offset + 3] << 8) + (binaryForm[offset + 2] << 0) > binaryForm.Length - offset)
            {
                //
                // Reported length of ACE ought to be no longer than the
                // length of the buffer passed in
                //

                throw new ArgumentOutOfRangeException(
                    nameof(binaryForm),
                    "Destination array is not long enough to copy all the required data. Check array length and offset.");
            }
        }

        //
        // Instantiates the most-derived ACE type based on the binary
        // representation of an ACE
        //

        public static GenericAce CreateFromBinaryForm(byte[] binaryForm, int offset)
        {
            GenericAce result;
            AceType type;

            //
            // Sanity check the header
            //

            VerifyHeader(binaryForm, offset);

            type = (AceType)binaryForm[offset];

            if (type == AceType.AccessAllowed ||
                type == AceType.AccessDenied ||
                type == AceType.SystemAudit ||
                type == AceType.SystemAlarm ||
                type == AceType.AccessAllowedCallback ||
                type == AceType.AccessDeniedCallback ||
                type == AceType.SystemAuditCallback ||
                type == AceType.SystemAlarmCallback)
            {
                AceQualifier qualifier;
                int accessMask;
                SecurityIdentifier sid;
                bool isCallback;
                byte[] opaque;

                if (true == CommonAce.ParseBinaryForm(binaryForm, offset, out qualifier, out accessMask, out sid, out isCallback, out opaque))
                {
                    AceFlags flags = (AceFlags)binaryForm[offset + 1];
                    result = new CommonAce(flags, qualifier, accessMask, sid, isCallback, opaque);
                }
                else
                {
                    goto InvalidParameter;
                }
            }
            else if (type == AceType.AccessAllowedObject ||
                type == AceType.AccessDeniedObject ||
                type == AceType.SystemAuditObject ||
                type == AceType.SystemAlarmObject ||
                type == AceType.AccessAllowedCallbackObject ||
                type == AceType.AccessDeniedCallbackObject ||
                type == AceType.SystemAuditCallbackObject ||
                type == AceType.SystemAlarmCallbackObject)
            {
                AceQualifier qualifier;
                int accessMask;
                SecurityIdentifier sid;
                ObjectAceFlags objectFlags;
                Guid objectAceType;
                Guid inheritedObjectAceType;
                bool isCallback;
                byte[] opaque;

                if (true == ObjectAce.ParseBinaryForm(binaryForm, offset, out qualifier, out accessMask, out sid, out objectFlags, out objectAceType, out inheritedObjectAceType, out isCallback, out opaque))
                {
                    AceFlags flags = (AceFlags)binaryForm[offset + 1];
                    result = new ObjectAce(flags, qualifier, accessMask, sid, objectFlags, objectAceType, inheritedObjectAceType, isCallback, opaque);
                }
                else
                {
                    goto InvalidParameter;
                }
            }
            else if (type == AceType.AccessAllowedCompound)
            {
                int accessMask;
                CompoundAceType compoundAceType;
                SecurityIdentifier sid;

                if (true == CompoundAce.ParseBinaryForm(binaryForm, offset, out accessMask, out compoundAceType, out sid))
                {
                    AceFlags flags = (AceFlags)binaryForm[offset + 1];
                    result = new CompoundAce(flags, accessMask, compoundAceType, sid);
                }
                else
                {
                    goto InvalidParameter;
                }
            }
            else
            {
                AceFlags flags = (AceFlags)binaryForm[offset + 1];
                byte[] opaque = null;
                int aceLength = (binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8);

                if (aceLength % 4 != 0)
                {
                    goto InvalidParameter;
                }

                int opaqueLength = aceLength - HeaderLength;

                if (opaqueLength > 0)
                {
                    opaque = new byte[opaqueLength];

                    for (int i = 0; i < opaqueLength; i++)
                    {
                        opaque[i] = binaryForm[offset + aceLength - opaqueLength + i];
                    }
                }

                result = new CustomAce(type, flags, opaque);
            }

            //
            // As a final check, confirm that the advertised ACE header length
            // was the actual parsed length
            //

            if (((!(result is ObjectAce)) && ((binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8) != result.BinaryLength))
                //
                // This is needed because object aces created through ADSI have the advertised ACE length
                // greater than the actual length by 32 (bug in ADSI).
                //
                || ((result is ObjectAce) && ((binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8) != result.BinaryLength) && (((binaryForm[offset + 2] << 0) + (binaryForm[offset + 3] << 8) - 32) != result.BinaryLength)))
            {
                goto InvalidParameter;
            }

            return result;

            InvalidParameter:

            throw new ArgumentException(
                "The binary form of an ACE object is invalid.",
                nameof(binaryForm));
        }

        public static GenericAce CreateFromSddl(string sddlForm)
        {
            string[] fields = sddlForm.Split(';');
            if (fields.Length != 6)
            {
                throw new ArgumentException(
                    "Invalid number of components in SDDL string.",
                    nameof(sddlForm));
            }

            //
            // Parse type
            //

            AceType type;
            try
            {
                type = (AceType)Utils.AceTypes[fields[0]];
            }
            catch (KeyNotFoundException)
            {
                throw new ArgumentException("Unsupported ACE type.", nameof(sddlForm));
            }

            //
            // Parse flags
            //

            Match flagsMatch = Regex.Match(fields[1], $"^({string.Join("|", Utils.AceFlags.Values)})*$");
            if (!flagsMatch.Success)
            {
                throw new ArgumentException("Invalid ACE flags.", nameof(sddlForm));
            }

            AceFlags flags = flagsMatch.Groups[1].Captures.Cast<Capture>()
                                       .Select(capture => capture.Value)
                                       .Aggregate(AceFlags.None, (current, flagString) => current | (AceFlags)Utils.AceFlags[flagString]);

            //
            // Parse rights
            //

            int accessMask = 0;
            if (!string.IsNullOrEmpty(fields[2]))
            {
                uint unsignedAccessMask = Convert.ToUInt32(fields[2], 16);
                unchecked
                {
                    accessMask = (int)unsignedAccessMask;
                }
            }

            //
            // Parse object GUID
            //

            Guid objectGuid = Guid.Empty;
            if (!string.IsNullOrEmpty(fields[3]))
            {
                objectGuid = Guid.ParseExact(fields[3], "D");
            }

            //
            // Parse inherited object GUID
            //

            Guid inheritObjectGuid = Guid.Empty;
            if (!string.IsNullOrEmpty(fields[4]))
            {
                inheritObjectGuid = Guid.ParseExact(fields[4], "D");
            }

            //
            // Parse SID
            //

            SecurityIdentifier sid = new SecurityIdentifier(fields[5]);

            //
            // Now create the correct type of ACE
            //

            ObjectAceFlags objectAceFlags = ObjectAceFlags.None;
            objectAceFlags |= objectGuid != Guid.Empty ? ObjectAceFlags.ObjectAceTypePresent : ObjectAceFlags.None;
            objectAceFlags |= inheritObjectGuid != Guid.Empty ? ObjectAceFlags.InheritedObjectAceTypePresent : ObjectAceFlags.None;

            AceQualifier qualifier = QualifiedAce.QualifierFromType(type, out bool isCallback);

            if (!objectAceFlags.HasFlag(ObjectAceFlags.ObjectAceTypePresent) &&
                !objectAceFlags.HasFlag(ObjectAceFlags.InheritedObjectAceTypePresent))
            {
                return new CommonAce(flags, qualifier, accessMask, sid, isCallback, null);
            }
            else
            {
                return new ObjectAce(flags, qualifier, accessMask, sid, objectAceFlags, objectGuid, inheritObjectGuid, isCallback, null);
            }
        }

        #endregion

        #region Public Properties

        //
        // Returns the numeric type of the ACE
        // Since not all ACE types are known, this
        // property returns a byte value.
        //

        public AceType AceType
        {
            get
            {
                return _type;
            }
        }

        //
        // Sets and retrieves the flags associated with the ACE
        // No checks are performed when setting the flags.
        //

        public AceFlags AceFlags
        {
            get
            {
                return _flags;
            }

            set
            {
                _flags = value;
            }
        }

        public bool IsInherited
        {
            get
            {
                return ((this.AceFlags & AceFlags.Inherited) != 0);
            }
        }

        public InheritanceFlags InheritanceFlags
        {
            get
            {
                InheritanceFlags flags = 0;

                if ((this.AceFlags & AceFlags.ContainerInherit) != 0)
                {
                    flags |= InheritanceFlags.ContainerInherit;
                }

                if ((this.AceFlags & AceFlags.ObjectInherit) != 0)
                {
                    flags |= InheritanceFlags.ObjectInherit;
                }

                return flags;
            }
        }

        public PropagationFlags PropagationFlags
        {
            get
            {
                PropagationFlags flags = 0;

                if ((this.AceFlags & AceFlags.InheritOnly) != 0)
                {
                    flags |= PropagationFlags.InheritOnly;
                }

                if ((this.AceFlags & AceFlags.NoPropagateInherit) != 0)
                {
                    flags |= PropagationFlags.NoPropagateInherit;
                }

                return flags;
            }
        }

        public AuditFlags AuditFlags
        {
            get
            {
                AuditFlags flags = 0;

                if ((this.AceFlags & AceFlags.SuccessfulAccess) != 0)
                {
                    flags |= AuditFlags.Success;
                }

                if ((this.AceFlags & AceFlags.FailedAccess) != 0)
                {
                    flags |= AuditFlags.Failure;
                }

                return flags;
            }
        }

        //
        // The value returned is really an unsigned short
        // A signed type is used for CLS compliance
        //

        public abstract int BinaryLength { get; }

        #endregion

        #region Public Methods

        //
        // Copies the binary representation of the ACE into a given array
        // starting at the given offset.
        //

        public abstract void GetBinaryForm(byte[] binaryForm, int offset);

        //
        // Cloning is performed by calling the from-binary static factory method
        // on the binary representation of the ACE.
        // Make this routine virtual if any leaf ACE class were to ever become
        // unsealed.
        //

        public GenericAce Copy()
        {
            //
            // Allocate an array big enough to hold the binary representation of the ACE
            //

            byte[] binaryForm = new byte[BinaryLength];

            GetBinaryForm(binaryForm, 0);

            return GenericAce.CreateFromBinaryForm(binaryForm, 0);
        }

        public sealed override bool Equals(object o)
        {
            if (o == null)
            {
                return false;
            }

            GenericAce ace = (o as GenericAce);

            if (ace == null)
            {
                return false;
            }

            if (this.AceType != ace.AceType ||
                this.AceFlags != ace.AceFlags)
            {
                return false;
            }

            int thisLength = this.BinaryLength;
            int aceLength = ace.BinaryLength;

            if (thisLength != aceLength)
            {
                return false;
            }

            byte[] array1 = new byte[thisLength];
            byte[] array2 = new byte[aceLength];

            this.GetBinaryForm(array1, 0);
            ace.GetBinaryForm(array2, 0);

            for (int i = 0; i < array1.Length; i++)
            {
                if (array1[i] != array2[i])
                {
                    return false;
                }
            }

            return true;
        }

        public sealed override int GetHashCode()
        {
            int binaryLength = BinaryLength;
            byte[] array = new byte[binaryLength];
            GetBinaryForm(array, 0);
            int result = 0, i = 0;

            //
            // For purposes of hash code computation,
            // treat the ACE as an array of ints (fortunately, its length is divisible by 4)
            // and simply XOR all these ints together
            //

            while (i < binaryLength)
            {
                int increment = ((int)array[i]) +
                                (((int)array[i + 1]) << 8) +
                                (((int)array[i + 2]) << 16) +
                                (((int)array[i + 3]) << 24);

                result ^= increment;
                i += 4;
            }

            return result;
        }

        public static bool operator ==(GenericAce left, GenericAce right)
        {
            object l = left;
            object r = right;

            if (l == null && r == null)
            {
                return true;
            }
            else if (l == null || r == null)
            {
                return false;
            }
            else
            {
                return left.Equals(right);
            }
        }

        public static bool operator !=(GenericAce left, GenericAce right)
        {
            return !(left == right);
        }

        public abstract string GetSddlForm();

        #endregion
    }
}

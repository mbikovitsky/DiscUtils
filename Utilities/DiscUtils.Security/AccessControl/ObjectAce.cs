using System;
using System.Diagnostics;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public sealed class ObjectAce : QualifiedAce
    {
        #region Private Members and Constants

        private ObjectAceFlags _objectFlags;
        private Guid _objectAceType;
        private Guid _inheritedObjectAceType;

        private const int ObjectFlagsLength = 4;
        private const int GuidLength = 16;

        #endregion

        #region Constructors

        public ObjectAce(AceFlags aceFlags, AceQualifier qualifier, int accessMask, SecurityIdentifier sid, ObjectAceFlags flags, Guid type, Guid inheritedType, bool isCallback, byte[] opaque)
            : base(TypeFromQualifier(isCallback, qualifier), aceFlags, accessMask, sid, opaque)
        {
            _objectFlags = flags;
            _objectAceType = type;
            _inheritedObjectAceType = inheritedType;
        }

        #endregion

        #region Private Methods

        //  
        // The following access mask bits in object aces may refer to an objectType that
        // identifies the property set, property, extended right, or type of child object to which the ACE applies
        //
        //    ADS_RIGHT_DS_CREATE_CHILD = 0x1, 
        //    ADS_RIGHT_DS_DELETE_CHILD = 0x2, 
        //    ADS_RIGHT_DS_SELF = 0x8,
        //    ADS_RIGHT_DS_READ_PROP = 0x10, 
        //    ADS_RIGHT_DS_WRITE_PROP = 0x20, 
        //    ADS_RIGHT_DS_CONTROL_ACCESS = 0x100
        //
        internal static readonly int AccessMaskWithObjectType = 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x100;

        private static AceType TypeFromQualifier(bool isCallback, AceQualifier qualifier)
        {
            switch (qualifier)
            {
                case AceQualifier.AccessAllowed:
                    return isCallback ? AceType.AccessAllowedCallbackObject : AceType.AccessAllowedObject;

                case AceQualifier.AccessDenied:
                    return isCallback ? AceType.AccessDeniedCallbackObject : AceType.AccessDeniedObject;

                case AceQualifier.SystemAudit:
                    return isCallback ? AceType.SystemAuditCallbackObject : AceType.SystemAuditObject;

                case AceQualifier.SystemAlarm:
                    return isCallback ? AceType.SystemAlarmCallbackObject : AceType.SystemAlarmObject;

                default:

                    throw new ArgumentOutOfRangeException(
                        nameof(qualifier),
                        "Enum value was out of legal range.");
            }
        }

        //
        // This method checks if the objectType matches with the specified object type
        // (Either both do not have an object type or they have the same object type)
        //
        internal bool ObjectTypesMatch(ObjectAceFlags objectFlags, Guid objectType)
        {
            if ((ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != (objectFlags & ObjectAceFlags.ObjectAceTypePresent))
            {
                return false;
            }

            if (((ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0) &&
                (!ObjectAceType.Equals(objectType)))
            {
                return false;
            }

            return true;
        }

        //
        // This method checks if the inheritedObjectType matches with the specified inherited object type
        // (Either both do not have an inherited object type or they have the same inherited object type)
        //
        internal bool InheritedObjectTypesMatch(ObjectAceFlags objectFlags, Guid inheritedObjectType)
        {
            if ((ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != (objectFlags & ObjectAceFlags.InheritedObjectAceTypePresent))
            {
                return false;
            }

            if (((ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0) &&
                (!InheritedObjectAceType.Equals(inheritedObjectType)))
            {
                return false;
            }

            return true;
        }

        #endregion

        #region Static Parser

        //
        // Called by GenericAce.CreateFromBinaryForm to parse the binary form
        // of the object ACE and extract the useful pieces
        //

        internal static bool ParseBinaryForm(
            byte[] binaryForm,
            int offset,
            out AceQualifier qualifier,
            out int accessMask,
            out SecurityIdentifier sid,
            out ObjectAceFlags objectFlags,
            out Guid objectAceType,
            out Guid inheritedObjectAceType,
            out bool isCallback,
            out byte[] opaque)
        {
            byte[] guidArray = new byte[GuidLength];

            //
            // Verify the ACE header
            //

            VerifyHeader(binaryForm, offset);

            //
            // Verify the length field
            //

            if (binaryForm.Length - offset < HeaderLength + AccessMaskLength + ObjectFlagsLength + SecurityIdentifier.MinBinaryLength)
            {
                goto InvalidParameter;
            }

            //
            // Identify callback ACE types
            //

            AceType type = (AceType)binaryForm[offset];

            if (type == AceType.AccessAllowedObject ||
                type == AceType.AccessDeniedObject ||
                type == AceType.SystemAuditObject ||
                type == AceType.SystemAlarmObject)
            {
                isCallback = false;
            }
            else if (type == AceType.AccessAllowedCallbackObject ||
                type == AceType.AccessDeniedCallbackObject ||
                type == AceType.SystemAuditCallbackObject ||
                type == AceType.SystemAlarmCallbackObject)
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

            if (type == AceType.AccessAllowedObject ||
                type == AceType.AccessAllowedCallbackObject)
            {
                qualifier = AceQualifier.AccessAllowed;
            }
            else if (type == AceType.AccessDeniedObject ||
                type == AceType.AccessDeniedCallbackObject)
            {
                qualifier = AceQualifier.AccessDenied;
            }
            else if (type == AceType.SystemAuditObject ||
                type == AceType.SystemAuditCallbackObject)
            {
                qualifier = AceQualifier.SystemAudit;
            }
            else if (type == AceType.SystemAlarmObject ||
                type == AceType.SystemAlarmCallbackObject)
            {
                qualifier = AceQualifier.SystemAlarm;
            }
            else
            {
                goto InvalidParameter;
            }

            int baseOffset = offset + HeaderLength;
            int offsetLocal = 0;

            accessMask =
                unchecked((int)(
                (((uint)binaryForm[baseOffset + 0]) << 0) +
                (((uint)binaryForm[baseOffset + 1]) << 8) +
                (((uint)binaryForm[baseOffset + 2]) << 16) +
                (((uint)binaryForm[baseOffset + 3]) << 24)));

            offsetLocal += AccessMaskLength;

            objectFlags =
                (ObjectAceFlags)(
                (((uint)binaryForm[baseOffset + offsetLocal + 0]) << 0) +
                (((uint)binaryForm[baseOffset + offsetLocal + 1]) << 8) +
                (((uint)binaryForm[baseOffset + offsetLocal + 2]) << 16) +
                (((uint)binaryForm[baseOffset + offsetLocal + 3]) << 24));

            offsetLocal += ObjectFlagsLength;

            if ((objectFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
            {
                for (int i = 0; i < GuidLength; i++)
                {
                    guidArray[i] = binaryForm[baseOffset + offsetLocal + i];
                }

                offsetLocal += GuidLength;
            }
            else
            {
                for (int i = 0; i < GuidLength; i++)
                {
                    guidArray[i] = 0;
                }
            }

            objectAceType = new Guid(guidArray);

            if ((objectFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
            {
                for (int i = 0; i < GuidLength; i++)
                {
                    guidArray[i] = binaryForm[baseOffset + offsetLocal + i];
                }

                offsetLocal += GuidLength;
            }
            else
            {
                for (int i = 0; i < GuidLength; i++)
                {
                    guidArray[i] = 0;
                }
            }

            inheritedObjectAceType = new Guid(guidArray);

            sid = new SecurityIdentifier(binaryForm, baseOffset + offsetLocal);

            opaque = null;

            int aceLength = (binaryForm[offset + 3] << 8) + (binaryForm[offset + 2] << 0);

            if (aceLength % 4 != 0)
            {
                goto InvalidParameter;
            }

            int opaqueLength = (aceLength - HeaderLength - AccessMaskLength - ObjectFlagsLength - (byte)sid.BinaryLength);

            if ((objectFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
            {
                opaqueLength -= GuidLength;
            }

            if ((objectFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
            {
                opaqueLength -= GuidLength;
            }

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
            objectFlags = 0;
            objectAceType = Guid.NewGuid();
            inheritedObjectAceType = Guid.NewGuid();
            isCallback = false;
            opaque = null;

            return false;
        }

        #endregion

        #region Public Properties

        //
        // Returns the object flags field of this ACE
        //

        public ObjectAceFlags ObjectAceFlags
        {
            get
            {
                return _objectFlags;
            }

            set
            {
                _objectFlags = value;
            }
        }

        //
        // Allows querying and setting the object type GUID for this ACE
        //

        public Guid ObjectAceType
        {
            get
            {
                return _objectAceType;
            }

            set
            {
                _objectAceType = value;
            }
        }

        //
        // Allows querying and setting the inherited object type
        // GUID for this ACE
        //

        public Guid InheritedObjectAceType
        {
            get
            {
                return _inheritedObjectAceType;
            }

            set
            {
                _inheritedObjectAceType = value;
            }
        }

        public /* sealed */ override int BinaryLength
        {
            get
            {
                //
                // The GUIDs may or may not be present depending on the object flags
                //

                int GuidLengths =
                    ((_objectFlags & ObjectAceFlags.ObjectAceTypePresent) != 0 ? GuidLength : 0) +
                    ((_objectFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0 ? GuidLength : 0);

                return (HeaderLength + AccessMaskLength + ObjectFlagsLength + GuidLengths + SecurityIdentifier.BinaryLength + OpaqueLength);
            }
        }

        public static int MaxOpaqueLength(bool isCallback)
        {
            return ushort.MaxValue - HeaderLength - AccessMaskLength - ObjectFlagsLength - 2 * GuidLength - SecurityIdentifier.MaxBinaryLength;
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
            // Store the object flags in the big-endian format
            //

            binaryForm[baseOffset + offsetLocal + 0] = (byte)(((uint)ObjectAceFlags) >> 0);
            binaryForm[baseOffset + offsetLocal + 1] = (byte)(((uint)ObjectAceFlags) >> 8);
            binaryForm[baseOffset + offsetLocal + 2] = (byte)(((uint)ObjectAceFlags) >> 16);
            binaryForm[baseOffset + offsetLocal + 3] = (byte)(((uint)ObjectAceFlags) >> 24);

            offsetLocal += ObjectFlagsLength;

            //
            // Store the object type GUIDs if present
            //

            if ((ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) != 0)
            {
                ObjectAceType.ToByteArray().CopyTo(binaryForm, baseOffset + offsetLocal);
                offsetLocal += GuidLength;
            }

            if ((ObjectAceFlags & ObjectAceFlags.InheritedObjectAceTypePresent) != 0)
            {
                InheritedObjectAceType.ToByteArray().CopyTo(binaryForm, baseOffset + offsetLocal);
                offsetLocal += GuidLength;
            }

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

        public override string GetSddlForm()
        {
            AceType type;
            string objectGuid;
            string inheritedObjectGuid;

            if (AceType == AceType.AccessAllowedObject &&
                !ObjectAceFlags.HasFlag(ObjectAceFlags.ObjectAceTypePresent) &&
                !ObjectAceFlags.HasFlag(ObjectAceFlags.InheritedObjectAceTypePresent))
            {
                // If ace_type is ACCESS_ALLOWED_OBJECT_ACE_TYPE and neither object_guid nor inherit_object_guid
                // has a GUID specified, then ConvertStringSecurityDescriptorToSecurityDescriptor
                // converts ace_type to ACCESS_ALLOWED_ACE_TYPE.

                type = AceType.AccessAllowed;

                objectGuid = "";

                inheritedObjectGuid = "";
            }
            else
            {
                type = AceType;

                objectGuid =
                    ObjectAceType.Equals(Guid.Empty)
                        ? ""
                        : ObjectAceType.ToString("D");

                inheritedObjectGuid =
                    InheritedObjectAceType.Equals(Guid.Empty)
                        ? ""
                        : InheritedObjectAceType.ToString("D");
            }

            return
                $"{Utils.AceTypes[AceType]};{Utils.AceFlagsToString(AceFlags)};0x{AccessMask:x};{objectGuid};{inheritedObjectGuid};{SecurityIdentifier.Value}";
        }

        #endregion
    }
}

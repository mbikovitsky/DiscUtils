using System;
using System.Diagnostics;
using System.Globalization;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class QualifiedAce : KnownAce
    {
        #region Private Members

        private readonly bool _isCallback;
        private readonly AceQualifier _qualifier;
        private byte[] _opaque;

        #endregion

        #region Private Methods

        private AceQualifier QualifierFromType(AceType type, out bool isCallback)
        {
            //
            // Better performance might be achieved by using a hard-coded table
            //

            switch (type)
            {
                case AceType.AccessAllowed:
                    isCallback = false;
                    return AceQualifier.AccessAllowed;

                case AceType.AccessDenied:
                    isCallback = false;
                    return AceQualifier.AccessDenied;

                case AceType.SystemAudit:
                    isCallback = false;
                    return AceQualifier.SystemAudit;

                case AceType.SystemAlarm:
                    isCallback = false;
                    return AceQualifier.SystemAlarm;

                case AceType.AccessAllowedCallback:
                    isCallback = true;
                    return AceQualifier.AccessAllowed;

                case AceType.AccessDeniedCallback:
                    isCallback = true;
                    return AceQualifier.AccessDenied;

                case AceType.SystemAuditCallback:
                    isCallback = true;
                    return AceQualifier.SystemAudit;

                case AceType.SystemAlarmCallback:
                    isCallback = true;
                    return AceQualifier.SystemAlarm;

                case AceType.AccessAllowedObject:
                    isCallback = false;
                    return AceQualifier.AccessAllowed;

                case AceType.AccessDeniedObject:
                    isCallback = false;
                    return AceQualifier.AccessDenied;

                case AceType.SystemAuditObject:
                    isCallback = false;
                    return AceQualifier.SystemAudit;

                case AceType.SystemAlarmObject:
                    isCallback = false;
                    return AceQualifier.SystemAlarm;

                case AceType.AccessAllowedCallbackObject:
                    isCallback = true;
                    return AceQualifier.AccessAllowed;

                case AceType.AccessDeniedCallbackObject:
                    isCallback = true;
                    return AceQualifier.AccessDenied;

                case AceType.SystemAuditCallbackObject:
                    isCallback = true;
                    return AceQualifier.SystemAudit;

                case AceType.SystemAlarmCallbackObject:
                    isCallback = true;
                    return AceQualifier.SystemAlarm;

                default:

                    //
                    // Indicates a bug in the implementation, not in user's code
                    //

                    Debug.Assert(false, "Invalid ACE type");
                    // Replacing SystemException with InvalidOperationException. It's not a perfect fit,
                    // but it's the best exception type available to indicate a failure because
                    // of a bug in the ACE itself.
                    throw new InvalidOperationException();
            }
        }

        #endregion

        #region Constructors

        internal QualifiedAce(AceType type, AceFlags flags, int accessMask, SecurityIdentifier sid, byte[] opaque)
            : base(type, flags, accessMask, sid)
        {
            _qualifier = QualifierFromType(type, out _isCallback);
            SetOpaque(opaque);
        }

        #endregion

        #region Public Properties

        //
        // Returns the qualifier associated with this ACE
        // Qualifier is determined at object creation time and
        // can not be changed since doing so would change the ACE type
        // which is in itself an immutable property
        //

        public AceQualifier AceQualifier
        {
            get
            {
                return _qualifier;
            }
        }

        //
        // Returns 'true' if this ACE type supports resource
        // manager-specific callback data.
        // This property is determined at object creation time
        // and can not be changed.
        //

        public bool IsCallback
        {
            get
            {
                return _isCallback;
            }
        }

        //
        // ACE types that support opaque data must also specify the maximum
        // allowed length of such data
        //

        internal abstract int MaxOpaqueLengthInternal { get; }

        //
        // Returns the length of opaque blob
        //

        public int OpaqueLength
        {
            get
            {
                if (_opaque != null)
                {
                    return _opaque.Length;
                }
                else
                {
                    return 0;
                }
            }
        }

        #endregion

        #region Public Methods

        //
        // Methods to set and retrieve the opaque portion of the ACE
        // NOTE: the caller is given the actual (not cloned) copy of the data
        //

        public byte[] GetOpaque()
        {
            return _opaque;
        }

        public void SetOpaque(byte[] opaque)
        {
            if (opaque != null)
            {
                if (opaque.Length > MaxOpaqueLengthInternal)
                {
                    throw new ArgumentOutOfRangeException(
nameof(opaque),
                        string.Format(CultureInfo.CurrentCulture, SR.ArgumentOutOfRange_ArrayLength, 0, MaxOpaqueLengthInternal));
                }
                else if (opaque.Length % 4 != 0)
                {
                    throw new ArgumentOutOfRangeException(
nameof(opaque),
                        string.Format(CultureInfo.CurrentCulture, SR.ArgumentOutOfRange_ArrayLengthMultiple, 4));
                }
            }

            _opaque = opaque;
        }
        #endregion
    }
}

using System;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    //
    // Every known ACE type contains an access mask and a SID
    //


    public abstract class KnownAce : GenericAce
    {
        #region Private Members

        //
        // All known ACE types contain an access mask and a SID
        //

        private int _accessMask;
        private SecurityIdentifier _sid;

        #endregion

        #region Internal Constants

        internal const int AccessMaskLength = 4;

        #endregion

        #region Constructors

        internal KnownAce(AceType type, AceFlags flags, int accessMask, SecurityIdentifier securityIdentifier)
            : base(type, flags)
        {
            if (securityIdentifier == null)
            {
                throw new ArgumentNullException(nameof(securityIdentifier));
            }

            //
            // The values are set by invoking the properties.
            //

            AccessMask = accessMask;
            SecurityIdentifier = securityIdentifier;
        }

        #endregion

        #region Public Properties

        //
        // Sets and retrieves the access mask associated with this ACE.
        // The access mask can be any 32-bit value.
        //

        public int AccessMask
        {
            get
            {
                return _accessMask;
            }

            set
            {
                _accessMask = value;
            }
        }

        //
        // Sets and retrieves the SID associated with this ACE.
        // The SID can not be null, but can otherwise be any valid
        // security identifier.
        //

        public SecurityIdentifier SecurityIdentifier
        {
            get
            {
                return _sid;
            }

            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                _sid = value;
            }
        }
        #endregion
    }
}

using System;
using DiscUtils.Security.Principal;

namespace DiscUtils.Security.AccessControl
{
    public abstract class AccessRule : AuthorizationRule
    {
        #region Private Methods

        private readonly AccessControlType _type;

        #endregion

        #region Constructors

        protected AccessRule(
            IdentityReference identity,
            int accessMask,
            bool isInherited,
            InheritanceFlags inheritanceFlags,
            PropagationFlags propagationFlags,
            AccessControlType type)
            : base(identity, accessMask, isInherited, inheritanceFlags, propagationFlags)
        {
            if (type != AccessControlType.Allow &&
                type != AccessControlType.Deny)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(type),
                    SR.ArgumentOutOfRange_Enum);
            }

            if (inheritanceFlags < InheritanceFlags.None || inheritanceFlags > (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(inheritanceFlags),
                    SR.Format(SR.Argument_InvalidEnumValue, inheritanceFlags, "InheritanceFlags"));
            }

            if (propagationFlags < PropagationFlags.None || propagationFlags > (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(propagationFlags),
                    SR.Format(SR.Argument_InvalidEnumValue, inheritanceFlags, "PropagationFlags"));
            }

            _type = type;
        }

        #endregion

        #region Properties

        public AccessControlType AccessControlType
        {
            get { return _type; }
        }

        #endregion
    }
}

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
                    "Enum value was out of legal range.");
            }

            if (inheritanceFlags < InheritanceFlags.None || inheritanceFlags > (InheritanceFlags.ObjectInherit | InheritanceFlags.ContainerInherit))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(inheritanceFlags),
                    $"The value '{inheritanceFlags}' is not valid for this usage of the type {InheritanceFlags}.");
            }

            if (propagationFlags < PropagationFlags.None || propagationFlags > (PropagationFlags.NoPropagateInherit | PropagationFlags.InheritOnly))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(propagationFlags),
                    $"The value '{propagationFlags}' is not valid for this usage of the type {PropagationFlags}.");
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

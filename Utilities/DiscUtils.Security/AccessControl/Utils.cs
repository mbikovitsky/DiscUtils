using System;
using System.Text;

namespace DiscUtils.Security.AccessControl
{
    internal static class Utils
    {
        /// <summary>
        /// Converts an ACE type to the corresponding SDDL string.
        /// </summary>
        /// <exception cref="NotImplementedException"></exception>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public static string AceTypeToString(AceType type)
        {
            switch (type)
            {
                case AceType.AccessAllowed:
                    return "A";
                case AceType.AccessDenied:
                    return "D";
                case AceType.SystemAudit:
                    return "AU";
                case AceType.SystemAlarm:
                    return "AL";
                case AceType.AccessAllowedObject:
                    return "OA";
                case AceType.AccessDeniedObject:
                    return "OD";
                case AceType.SystemAuditObject:
                    return "OU";
                case AceType.SystemAlarmObject:
                    return "OL";
                case AceType.AccessAllowedCallback:
                    return "XA";
                case AceType.AccessDeniedCallback:
                    return "XD";
                case AceType.AccessAllowedCallbackObject:
                    return "ZA";
                case AceType.SystemAuditCallback:
                    return "XU";

                case AceType.AccessAllowedCompound:
                case AceType.AccessDeniedCallbackObject:
                case AceType.SystemAlarmCallback:
                case AceType.SystemAuditCallbackObject:
                case AceType.SystemAlarmCallbackObject:
                    throw new NotImplementedException();

                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }

        /// <summary>
        /// Converts ACE flags to the corresponding SDDL string.
        /// </summary>
        public static string AceFlagsToString(AceFlags flags)
        {
            StringBuilder result = new StringBuilder();

            if (flags.HasFlag(AceFlags.ContainerInherit))
            {
                result.Append("CI");
            }

            if (flags.HasFlag(AceFlags.ObjectInherit))
            {
                result.Append("OI");
            }

            if (flags.HasFlag(AceFlags.NoPropagateInherit))
            {
                result.Append("NP");
            }

            if (flags.HasFlag(AceFlags.InheritOnly))
            {
                result.Append("IO");
            }

            if (flags.HasFlag(AceFlags.Inherited))
            {
                result.Append("ID");
            }

            if (flags.HasFlag(AceFlags.SuccessfulAccess))
            {
                result.Append("SA");
            }

            if (flags.HasFlag(AceFlags.FailedAccess))
            {
                result.Append("FA");
            }

            return result.ToString();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Text;

namespace DiscUtils.Security.AccessControl
{
    internal static class Utils
    {
        public static readonly EnumStringDictionary AceTypes = new EnumStringDictionary(new Dictionary<Enum, string>
        {
            { AceType.AccessAllowed, "A" },
            { AceType.AccessDenied, "D" },
            { AceType.SystemAudit, "AU" },
            { AceType.SystemAlarm, "AL" },
            { AceType.AccessAllowedObject, "OA" },
            { AceType.AccessDeniedObject, "OD" },
            { AceType.SystemAuditObject, "OU" },
            { AceType.SystemAlarmObject, "OL" },
            { AceType.AccessAllowedCallback, "XA" },
            { AceType.AccessDeniedCallback, "XD" },
            { AceType.AccessAllowedCallbackObject, "ZA" },
            { AceType.SystemAuditCallback, "XU" },
        });

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

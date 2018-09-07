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

        public static readonly EnumStringDictionary AceFlags = new EnumStringDictionary(new Dictionary<Enum, string>
        {
            { AccessControl.AceFlags.ContainerInherit, "CI" },
            { AccessControl.AceFlags.ObjectInherit, "OI" },
            { AccessControl.AceFlags.NoPropagateInherit, "NP" },
            { AccessControl.AceFlags.InheritOnly, "IO" },
            { AccessControl.AceFlags.Inherited, "ID" },
            { AccessControl.AceFlags.SuccessfulAccess, "SA" },
            { AccessControl.AceFlags.FailedAccess, "FA" }
        });

        /// <summary>
        /// Converts ACE flags to the corresponding SDDL string.
        /// </summary>
        public static string AceFlagsToString(AceFlags flags)
        {
            StringBuilder result = new StringBuilder();

            foreach (KeyValuePair<Enum, string> pair in AceFlags)
            {
                if (flags.HasFlag(pair.Key))
                {
                    result.Append(pair.Value);
                }
            }

            return result.ToString();
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

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

        public static readonly IReadOnlyDictionary<string, Enum> AccessRights = new Dictionary<string, Enum>
        {
            { "GA", AccessControl.AccessRights.GenericAll },
            { "GR", AccessControl.AccessRights.GenericRead },
            { "GW", AccessControl.AccessRights.GenericWrite },
            { "GX", AccessControl.AccessRights.GenericExecute },

            { "RC", AccessControl.AccessRights.ReadControl },
            { "SD", AccessControl.AccessRights.Delete },
            { "WD", AccessControl.AccessRights.WriteDac },
            { "WO", AccessControl.AccessRights.WriteOwner },

            { "RP", AccessControl.AccessRights.AdsRightDsReadProp },
            { "WP", AccessControl.AccessRights.AdsRightDsWriteProp },
            { "CC", AccessControl.AccessRights.AdsRightDsCreateChild },
            { "DC", AccessControl.AccessRights.AdsRightDsDeleteChild },
            { "LC", AccessControl.AccessRights.AdsRightActrlDsList },
            { "SW", AccessControl.AccessRights.AdsRightDsSelf },
            { "LO", AccessControl.AccessRights.AdsRightDsListObject },
            { "DT", AccessControl.AccessRights.AdsRightDsDeleteTree },
            { "CR", AccessControl.AccessRights.AdsRightDsControlAccess },

            { "FA", AccessControl.AccessRights.FileAllAccess },
            { "FR", AccessControl.AccessRights.FileGenericRead },
            { "FW", AccessControl.AccessRights.FileGenericWrite },
            { "FX", AccessControl.AccessRights.FileGenericExecute },

            { "KA", AccessControl.AccessRights.KeyAllAccess },
            { "KR", AccessControl.AccessRights.KeyRead },
            { "KW", AccessControl.AccessRights.KeyWrite },
            { "KX", AccessControl.AccessRights.KeyExecute },

            { "NR", AccessControl.AccessRights.SystemMandatoryLabelNoReadUp },
            { "NW", AccessControl.AccessRights.SystemMandatoryLabelNoWriteUp },
            { "NX", AccessControl.AccessRights.SystemMandatoryLabelNoExecuteUp },
        };

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

        public static IEnumerable<Enum> ParseFlagString(string stringToParse, IReadOnlyDictionary<string, Enum> dictionary)
        {
            Match flagsMatch = Regex.Match(stringToParse, $"^({string.Join("|", dictionary.Keys.Select(Regex.Escape))})*$");
            if (!flagsMatch.Success)
            {
                throw new ArgumentException("Invalid flags.", nameof(stringToParse));
            }

            return flagsMatch.Groups[1]
                             .Captures
                             .Cast<Capture>()
                             .Select(capture => dictionary[capture.Value]);
        }
    }
}

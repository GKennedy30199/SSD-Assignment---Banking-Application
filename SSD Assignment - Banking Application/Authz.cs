using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SSD_Assignment___Banking_Application
{
    public static class Authz
    {
        public const string TellersGroup = @"ITSLIGO\Bank Tellers";
        public const string AdminsGroup = @"ITSLIGO\Bank Teller Administrators";


        public static string CurrentUser()
        {
            return WindowsIdentity.GetCurrent()?.Name ?? Environment.UserName;
        }

        private static bool IsCurrentUserIn(string group)
        {
            using var wi = WindowsIdentity.GetCurrent();
            var wp = new WindowsPrincipal(wi);
            return wp.IsInRole(group);
        }

        public static void DemandTeller()
        {
            string user = CurrentUser();
            bool ok = IsCurrentUserIn(TellersGroup);

            // log the attempt
            Audit.LogLogin(user, ok, ok ? null : "User not in Bank Tellers group");

            if (!ok)
            {
                throw new UnauthorizedAccessException("You are not authorised to use this application.");
            }
        }

        public static void DemandAdmin()
        {
            string user = CurrentUser();
            bool ok = IsCurrentUserIn(AdminsGroup);

            // log the attempt
            Audit.LogLogin(user, ok, ok ? null : "User not in Bank Teller Administrators group");

            if (!ok)
            {
                throw new UnauthorizedAccessException("Administrator approval required.");
            }
        }
    }
}
 

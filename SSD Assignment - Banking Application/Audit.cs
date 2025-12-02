using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace SSD_Assignment___Banking_Application
{
    public static class Audit
    {
        private const string Source = "SSD Banking Application";
        private const string LogName = "Application";

        static Audit()
        {
            try
            {
                if (!EventLog.SourceExists(Source))
                {
                    EventLog.CreateEventSource(Source, LogName);
                }
            }
            catch
            {
                // Ignore exceptions related to event log source creation
            }
        }

        public static void LogTransaction(string teller, string accountNo, string accountHolder,
                                              string transactionType, double amount = 0.0,
                                              string reason = null)
        {
            string where = GetWhere();
            string when = DateTimeOffset.UtcNow.ToString("o");
            string how = GetAppMetadata();

            string msg = $"WHO1={teller}; WHO2=Acct:{accountNo}, Holder:{accountHolder}; " +
                         $"WHAT={transactionType}; AMOUNT={amount:F2}; " +
                         $"WHY={(string.IsNullOrWhiteSpace(reason) ? "N/A" : reason)}; " +
                         $"WHERE={where}; WHEN={when}; HOW={how}";

            EventLog.WriteEntry(Source, msg, EventLogEntryType.Information,1000);
        }
        public static void LogLogin(string user, bool success, string reason = null)
        {
            string where = GetWhere();
            string when = DateTimeOffset.UtcNow.ToString("o");
            string how = GetAppMetadata();

            string msg = $"LOGIN User={user}; Result={(success ? "SUCCESS" : "FAIL")}; " +
                         $"Reason={(reason ?? "N/A")}; WHERE={where}; WHEN={when}; HOW={how}";

            EventLogEntryType type = success ? EventLogEntryType.Information : EventLogEntryType.FailureAudit;
            EventLog.WriteEntry(Source, msg, type, 1001);
        }

        private static string GetWhere()
        {
            try
            {
                var sid = WindowsIdentity.GetCurrent()?.User?.Value ?? "UnknownSID";
                var mac = NetworkInterface.GetAllNetworkInterfaces()
                          .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up &&
                                               n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                          ?.GetPhysicalAddress()?.ToString();
                return $"SID={sid}; MAC={(string.IsNullOrWhiteSpace(mac) ? "N/A" : mac)}";
            }
            catch
            {
                return "SID=Unknown; MAC=N/A";
            }
        }

        private static string GetAppMetadata()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var name = asm.GetName();
                var version = name.Version?.ToString() ?? "0.0.0";
                var path = asm.Location;
                using var sha = SHA256.Create();
                var hash = BitConverter.ToString(sha.ComputeHash(System.IO.File.ReadAllBytes(path))).Replace("-", "");
                return $"Name={name.Name}; Version={version}; SHA256={hash}";
            }
            catch { return "Name=SSDApp; Version=Unknown; SHA256=N/A"; }
        }
    }

}

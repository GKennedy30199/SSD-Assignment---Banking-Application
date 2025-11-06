using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

//S00180333
namespace SSD_Assignment___Banking_Application
{
    public static class Crypto
    {
        private static byte[] Key
        {
            get
            {
                string? b64 = Environment.GetEnvironmentVariable("BANK_APP_KEY");
                if(string.IsNullOrWhiteSpace(b64))
                {
                    throw new InvalidOperationException("BANK_APP_KEY is not set in environment.");
                }
                return Convert.FromBase64String(b64);
            }
        }
        public static (byte[] ct, byte[] nonce, byte[] tag) EncryptString(string plaintext)
        {
            byte[] nonce=RandomNumberGenerator.GetBytes(12);
            byte[] pt=Encoding.UTF8.GetBytes(plaintext);
            byte[] ct=new byte[pt.Length];
            byte[] tag=new byte[16];

            using var aes=new AesGcm(Key);
            aes.Encrypt(nonce, pt, ct, tag);
            Array.Clear(pt, 0, pt.Length);
            return (ct, nonce, tag);
        }

        public static string DecryptToString(byte[] ct, byte[] nonce, byte[] tag)
        {
            byte[] pt=new byte[ct.Length];
            using var aes=new AesGcm(Key);
            aes.Decrypt(nonce, ct, tag, pt);
            try { return Encoding.UTF8.GetString(pt);
            }
            finally 
            {
                Array.Clear(pt, 0, pt.Length);
            }
           
        }
    }
}

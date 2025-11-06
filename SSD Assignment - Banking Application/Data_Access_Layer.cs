using Microsoft.Data.Sqlite;
using SSD_Assignment___Banking_Application;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Banking_Application
{
    public class Data_Access_Layer
    {

        private List<Bank_Account> accounts;
        public static String databaseName = "Banking Database.db";
        private static Data_Access_Layer instance = new Data_Access_Layer();

        private Data_Access_Layer()//Singleton Design Pattern (For Concurrency Control) - Use getInstance() Method Instead.
        {
            accounts = new List<Bank_Account>();
        }

        public static Data_Access_Layer getInstance()
        {
            return instance;
        }

        private SqliteConnection getDatabaseConnection()
        {

            String databaseConnectionString = new SqliteConnectionStringBuilder()
            {
                DataSource = Data_Access_Layer.databaseName,
                Mode = SqliteOpenMode.ReadWriteCreate
            }.ToString();

            return new SqliteConnection(databaseConnectionString);

        }

        private void initialiseDatabase()
        {
            using (var connection = getDatabaseConnection())
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText =
                @"
                    CREATE TABLE IF NOT EXISTS Bank_Accounts(    
                        accountNo TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        address_line_1 TEXT,
                        address_line_2 TEXT,
                        address_line_3 TEXT,
                        town TEXT NOT NULL,
                        balance REAL NOT NULL,
                        accountType INTEGER NOT NULL,
                        overdraftAmount REAL,
                        interestRate REAL
                    ) WITHOUT ROWID
                ";

                command.ExecuteNonQuery();
                
            }
        }

        public void loadBankAccounts()
        {
            if (!File.Exists(Data_Access_Layer.databaseName))
            {
                initialiseDatabase();
                return;
            }

            using (var connection = getDatabaseConnection())
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = "SELECT * FROM Bank_Accounts";
                SqliteDataReader dr = command.ExecuteReader();

                while (dr.Read())
                {
                    int accountType = dr.GetInt16(7);

                    //Common account fields
                    string accountNo = dr.GetString(0);

                    //Decrypt sensitive fields 
                    string name, addr1, addr2, addr3, town;

                    try
                    {
                        name = Crypto.DecryptToString(
                            (byte[])dr["Name_ct"],
                            (byte[])dr["Name_nonce"],
                            (byte[])dr["Name_tag"]);

                        addr1 = Crypto.DecryptToString(
                            (byte[])dr["Address1_ct"],
                            (byte[])dr["Address1_nonce"],
                            (byte[])dr["Address1_tag"]);

                        addr2 = Crypto.DecryptToString(
                            (byte[])dr["Address2_ct"],
                            (byte[])dr["Address2_nonce"],
                            (byte[])dr["Address2_tag"]);

                        addr3 = Crypto.DecryptToString(
                            (byte[])dr["Address3_ct"],
                            (byte[])dr["Address3_nonce"],
                            (byte[])dr["Address3_tag"]);

                        town = Crypto.DecryptToString(
                            (byte[])dr["Town_ct"],
                            (byte[])dr["Town_nonce"],
                            (byte[])dr["Town_tag"]);
                    }
                    catch
                    {
                        // Fallback for old plaintext records
                        name = dr.IsDBNull(1) ? "" : dr.GetString(1);
                        addr1 = dr.IsDBNull(2) ? "" : dr.GetString(2);
                        addr2 = dr.IsDBNull(3) ? "" : dr.GetString(3);
                        addr3 = dr.IsDBNull(4) ? "" : dr.GetString(4);
                        town = dr.IsDBNull(5) ? "" : dr.GetString(5);
                    }
                    double balance = dr.GetDouble(6);
                    //recreates correct account type
                    if (accountType == Account_Type.Current_Account)
                    {
                        Current_Account ca = new Current_Account
                        {
                            accountNo = accountNo,
                            name = name,
                            address_line_1 = addr1,
                            address_line_2 = addr2,
                            address_line_3 = addr3,
                            town = town,
                            balance = balance,
                            overdraftAmount = dr.GetDouble(8)
                        };
                        accounts.Add(ca);
                    }
                    else
                    {
                        Savings_Account sa = new Savings_Account
                        {
                            accountNo = accountNo,
                            name = name,
                            address_line_1 = addr1,
                            address_line_2 = addr2,
                            address_line_3 = addr3,
                            town = town,
                            balance = balance,
                            interestRate = dr.GetDouble(9)
                        };
                        accounts.Add(sa);
                    }
                }
            }
        }

        public String addBankAccount(Bank_Account ba) 
        {

            if (ba.GetType() == typeof(Current_Account))
                ba = (Current_Account)ba;
            else
                ba = (Savings_Account)ba;

            accounts.Add(ba);
            var (nameCt, nameNonce, nameTag) = Crypto.EncryptString(ba.name);
            var (addr1Ct, addr1Nonce, addr1Tag) = Crypto.EncryptString(ba.address_line_1);
            var (addr2Ct, addr2Nonce, addr2Tag) = Crypto.EncryptString(ba.address_line_2);
            var (addr3Ct, addr3Nonce, addr3Tag) = Crypto.EncryptString(ba.address_line_3);
            var (townCt, townNonce, townTag) = Crypto.EncryptString(ba.town);


            using (var connection = getDatabaseConnection())
            {
                connection.Open();
                var command = connection.CreateCommand();
                command.CommandText = @"
    INSERT INTO Bank_Accounts
    (AccountNo, Name,
     Name_ct, Name_nonce, Name_tag,
     Address1_ct, Address1_nonce, Address1_tag,
     Address2_ct, Address2_nonce, Address2_tag,
     Address3_ct, Address3_nonce, Address3_tag,
     Town_ct, Town_nonce, Town_tag,
     Balance, AccountType, Overdraft, InterestRate)
    VALUES (
     @acct, @name,
     @nct, @nnonce, @ntag,
     @a1ct, @a1nonce, @a1tag,
     @a2ct, @a2nonce, @a2tag,
     @a3ct, @a3nonce, @a3tag,
     @tct, @tnonce, @ttag,
     @bal, @type, @od, @ir
    );";


                command.Parameters.AddWithValue("@acct", ba.accountNo);
                command.Parameters.AddWithValue("@name", ba.name);
                command.Parameters.AddWithValue("@nct", nameCt);
                command.Parameters.AddWithValue("@nnonce", nameNonce);
                command.Parameters.AddWithValue("@ntag", nameTag);

                command.Parameters.AddWithValue("@a1ct", addr1Ct);
                command.Parameters.AddWithValue("@a1nonce", addr1Nonce);
                command.Parameters.AddWithValue("@a1tag", addr1Tag);

                command.Parameters.AddWithValue("@a2ct", addr2Ct);
                command.Parameters.AddWithValue("@a2nonce", addr2Nonce);
                command.Parameters.AddWithValue("@a2tag", addr2Tag);

                command.Parameters.AddWithValue("@a3ct", addr3Ct);
                command.Parameters.AddWithValue("@a3nonce", addr3Nonce);
                command.Parameters.AddWithValue("@a3tag", addr3Tag);

                command.Parameters.AddWithValue("@tct", townCt);
                command.Parameters.AddWithValue("@tnonce", townNonce);
                command.Parameters.AddWithValue("@ttag", townTag);

                command.Parameters.AddWithValue("@bal", ba.balance);
                command.Parameters.AddWithValue("@type", (ba.GetType() == typeof(Current_Account)) ? 1 : 2);

             if (ba is Current_Account ca)
                {
                    command.Parameters.AddWithValue("@od", ca.overdraftAmount);
                    command.Parameters.AddWithValue("@ir", DBNull.Value);
                }

               else if (ba is Savings_Account sa)
                {
                    command.Parameters.AddWithValue("@od", DBNull.Value);
                    command.Parameters.AddWithValue("@ir", sa.interestRate);
                }

                    command.ExecuteNonQuery();

            }

            return ba.accountNo;

        }

        public Bank_Account findBankAccountByAccNo(String accNo) 
        { 
        
            foreach(Bank_Account ba in accounts)
            {

                if (ba.accountNo.Equals(accNo))
                {
                    return ba;
                }

            }

            return null; 
        }

        public bool closeBankAccount(String accNo) 
        {

            Bank_Account toRemove = null;
            
            foreach (Bank_Account ba in accounts)
            {

                if (ba.accountNo.Equals(accNo))
                {
                    toRemove = ba;
                    break;
                }

            }

            if (toRemove == null)
                return false;
            else
            {
                accounts.Remove(toRemove);

                using (var connection = getDatabaseConnection())
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "DELETE FROM Bank_Accounts WHERE accountNo = '" + toRemove.accountNo + "'";
                    command.ExecuteNonQuery();

                }

                return true;
            }

        }

        public bool lodge(String accNo, double amountToLodge)
        {

            Bank_Account toLodgeTo = null;

            foreach (Bank_Account ba in accounts)
            {

                if (ba.accountNo.Equals(accNo))
                {
                    ba.lodge(amountToLodge);
                    toLodgeTo = ba;
                    break;
                }

            }

            if (toLodgeTo == null)
                return false;
            else
            {

                using (var connection = getDatabaseConnection())
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "UPDATE Bank_Accounts SET balance = " + toLodgeTo.balance + " WHERE accountNo = '" + toLodgeTo.accountNo + "'";
                    command.ExecuteNonQuery();

                }

                return true;
            }

        }

        public bool withdraw(String accNo, double amountToWithdraw)
        {

            Bank_Account toWithdrawFrom = null;
            bool result = false;

            foreach (Bank_Account ba in accounts)
            {

                if (ba.accountNo.Equals(accNo))
                {
                    result = ba.withdraw(amountToWithdraw);
                    toWithdrawFrom = ba;
                    break;
                }

            }

            if (toWithdrawFrom == null || result == false)
                return false;
            else
            {

                using (var connection = getDatabaseConnection())
                {
                    connection.Open();
                    var command = connection.CreateCommand();
                    command.CommandText = "UPDATE Bank_Accounts SET balance = " + toWithdrawFrom.balance + " WHERE accountNo = '" + toWithdrawFrom.accountNo + "'";
                    command.ExecuteNonQuery();

                }

                return true;
            }

        }

    }
}

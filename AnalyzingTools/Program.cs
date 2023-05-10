using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace AnalyzingTools
{
    internal class Program
    {
        private const int _iterationCount = 10000;
        static void Main(string[] args)
        {
            var saltWord = "I've got a bucket of chicken";
            var bytes = Encoding.UTF8.GetBytes(saltWord);
            var password = "password";
            var stopWatch = new Stopwatch();

            Console.WriteLine("Original code");
            stopWatch.Start();
            var hash1 = GeneratePasswordHashUsingSalt(password, bytes);
            stopWatch.Stop();
            Console.WriteLine("Password hash: " + hash1);

            Console.WriteLine("Code elapsed at: " + stopWatch.ElapsedTicks);
            Console.WriteLine();

            Console.WriteLine("KeyDerivation code");
            stopWatch.Restart();
            var hash2 = GeneratePasswordHashUsingSaltOptimizedV2(password, bytes);
            stopWatch.Stop();
            Console.WriteLine("Password hash: " + hash2);

            Console.WriteLine("Code elapsed at: " + stopWatch.ElapsedTicks);
            Console.WriteLine();

            Console.WriteLine("Optimized code");
            stopWatch.Restart();
            var hash3 = GeneratePasswordHashUsingSaltOptimizedV1(password, bytes);
            stopWatch.Stop();
            Console.WriteLine("Password hash: " + hash3);

            Console.WriteLine("Code elapsed at: " + stopWatch.ElapsedTicks);
            Console.WriteLine();

            Console.WriteLine("Optimized code 2");
            stopWatch.Restart();
            var hash4 = GeneratePasswordHashUsingSaltOptimizedV3(password, bytes);
            stopWatch.Stop();
            Console.WriteLine("Password hash: " + hash4);

            Console.WriteLine("Code elapsed at: " + stopWatch.ElapsedTicks);

            Console.ReadLine();
        }

        public static string GeneratePasswordHashUsingSalt(string passwordText, byte[] salt)

        {
            var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, _iterationCount);
            var hash = pbkdf2.GetBytes(20);

            var hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            var passwordHash = Convert.ToBase64String(hashBytes);

            return passwordHash;
        }

        public static string GeneratePasswordHashUsingSaltOptimizedV1(string passwordText, byte[] salt)
        {
            byte[] hashValue;
            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordText, salt, _iterationCount))
            {
                hashValue = pbkdf2.GetBytes(36);
            }
            return Convert.ToBase64String(hashValue);
        }

        public static string GeneratePasswordHashUsingSaltOptimizedV2(string passwordText, byte[] salt)
        {
            return Convert.ToBase64String(KeyDerivation.Pbkdf2(
                password: passwordText,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: _iterationCount,
                numBytesRequested: 36));
        }

        public static string GeneratePasswordHashUsingSaltOptimizedV3(string passwordText, byte[] salt)
        {
            var hash = KeyDerivation.Pbkdf2(
                password: passwordText,
                salt: salt,
                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: _iterationCount,
                numBytesRequested: 20);

            var hashBytes = new byte[36];
            Array.Copy(salt, 0, hashBytes, 0, 16);
            Array.Copy(hash, 0, hashBytes, 16, 20);

            return Convert.ToBase64String(hashBytes);
        }
    }
}

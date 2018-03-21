using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace HIBP_Password_Checker
{
    class Program
    {
        static void Main()
        {



            while (true)
            {

                Console.WriteLine("Enter Password");
                string password = Console.ReadLine();

                var result = Task.Run((() => CheckPassword(password)));
                Console.WriteLine(result.Result);

            }



        }


        public static async Task<string> CheckPassword(string password)
        {

            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            string URL = "https://api.pwnedpasswords.com/range/";

            bool hashNotSecure = false;
            string result = string.Empty;
            string builder = string.Empty;

            HashAlgorithm hash = SHA1.Create();

            foreach (var aByte in hash.ComputeHash(Encoding.UTF8.GetBytes(password)))
            {
                builder += aByte.ToString("X2");
            }

            Console.WriteLine($"\nThis is the Unique Hash for {password} ---> {builder}");

            string urlParameters = builder.Substring(0, 5);
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(URL);

            await Task.Run(() =>
            {
                //send the reques with the first 5 chars of the Hash
                HttpResponseMessage response = client.GetAsync(urlParameters).Result;

                Console.WriteLine($"{response.RequestMessage.RequestUri.AbsoluteUri} --> RETURNS {response.StatusCode}");

                //read the content of the response sent back to me and split them into individual hashes.
                Task<string> receiveStream = response.Content.ReadAsStringAsync();
                string[] hashes = receiveStream.Result.Split('\n');

                //Get our hash minus the first 5
                string originalHashMinusFirst5 = builder.Substring(5, builder.Length - 5);
                Console.WriteLine($"This is the K Anon hash {originalHashMinusFirst5}");

                Console.WriteLine("\n****Foreach****");

                foreach (var x in hashes)
                {
                    string newHash = x;
                    int index = x.IndexOf(':');
                    newHash = newHash.Substring(0, index);

                    if (newHash == originalHashMinusFirst5)
                    {

                        result = $"{x}\nALERT PASSWORD NOT SECURE\n";
                        hashNotSecure = true;
                    }
                }

            });


            //Array of hashes minus the ifrst 5 characters
            if (!hashNotSecure)
            {
                result = "Password is secure\n";
            }


            return result;
        }

    }
}

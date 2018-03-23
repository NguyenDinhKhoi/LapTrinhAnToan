using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace UserPassHashCode
{
    public class SHA
    {
        public string SHA1(string pass)
        {
            SHA1CryptoServiceProvider sha1 = new SHA1CryptoServiceProvider();
            byte[] bs = System.Text.Encoding.UTF8.GetBytes(pass);
            bs = sha1.ComputeHash(bs);
            StringBuilder s = new StringBuilder();
            foreach(byte b in bs)
            {
                s.Append(b.ToString("X1"));
                
            }
            pass = s.ToString();
            return pass;
        }
    }
}

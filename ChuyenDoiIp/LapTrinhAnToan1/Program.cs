using System;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace LapTrinhAnToan1
{
    class Program
    {
        static void Main(string[] args)
        {
            //Bai 1 : Xac dinh ten may cuc bo + IP

            //  String strHostName = Dns.GetHostName();
            //  Console.WriteLine("Host Name : " + strHostName);

            //  IPHostEntry iphost = Dns.GetHostByName(strHostName);

            //  int ip = 0;
            //  foreach(IPAddress ipadress in iphost.AddressList)
            //  {
            //      Console.WriteLine("IP : " + ++ip + ": " + ipadress.ToString());
            //  }
        

            //Bai 2 : chuyen doi ten mien thanh Ip va nguoc lai
            string str;
            int a = -1;
            Console.WriteLine("Nhap 1 neu muon chuyen doi ten mien, 2 neu muon chuyen doi IP");
            a = int.Parse(Console.ReadLine());
            if(a == 1)
            {
                Console.WriteLine("Nhap ten mien muon chuyen doi: ");
                str = Console.ReadLine();
                IPHostEntry iphost = Dns.GetHostByName(str);
                foreach (IPAddress ipadress in iphost.AddressList)
                {
                    Console.WriteLine("IP : " + ipadress.ToString());
                    return;
                }
            }
            if(a==2)
            {
                Console.WriteLine("Nhap dia chi Ip muon chuyen doi thanh ten mien : ");
                str = Console.ReadLine();
                IPHostEntry iphost = Dns.Resolve(str);
                Console.WriteLine("IP :" + iphost.HostName);
                return;
            }
            else
            {
                Console.WriteLine("error");
            }
        }
    }
}

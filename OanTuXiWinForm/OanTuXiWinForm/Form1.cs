using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;

namespace OanTuXiWinForm
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        Socket server;
        EndPoint remote;
        private void Form1_Load(object sender, EventArgs e)
        {
            server = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            IPEndPoint ipe = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 3456);
            remote = (EndPoint)ipe;

        }

        private void button1_Click(object sender, EventArgs e)
        {
            txtSelect.Text = "Bua";
            byte[] sendData = Encoding.ASCII.GetBytes("0");
            server.SendTo(sendData, remote);
            byte[] receiveData = new byte[20];
            server.ReceiveFrom(receiveData, ref remote);
            txtResult.Text = Encoding.ASCII.GetString(receiveData);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            txtSelect.Text = "Keo";
            byte[] sendData = Encoding.ASCII.GetBytes("2");
            server.SendTo(sendData, remote);
            byte[] receiveData = new byte[20];
            server.ReceiveFrom(receiveData, ref remote);
            txtResult.Text = Encoding.ASCII.GetString(receiveData);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            txtSelect.Text = "Bao";
            byte[] sendData = Encoding.ASCII.GetBytes("1");
            server.SendTo(sendData, remote);
            byte[] receiveData = new byte[20];
            server.ReceiveFrom(receiveData, ref remote);
            txtResult.Text = Encoding.ASCII.GetString(receiveData);
        }

        private void Form1_FormClosed(object sender, FormClosedEventArgs e)
        {
            
        }
    }
}

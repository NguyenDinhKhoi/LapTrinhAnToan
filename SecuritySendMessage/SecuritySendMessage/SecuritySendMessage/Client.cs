using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;

namespace SecuritySendMessage
{
    public partial class Client : Form
    {
        public Client()
        {
            InitializeComponent();

            CheckForIllegalCrossThreadCalls = false;

            Connect();
        }
        
        //IP 
        IPEndPoint IP;
        //Socket(lỗ kết nối )
        Socket client;
        //Aes
        Aes_EcbEncrypt aes = new Aes_EcbEncrypt();
        // public key, secret key
        byte[] khoapublic;
        byte[] khoabimat;
        string keypublic;
        string keysecret;
        byte[] nhankey;
        byte[] nhankeydadoi;
        byte[] data;
        byte[] tinnhan;
        byte[] keypublicduocguilai = new byte[1024];
        //Sha
        SHA sha256 = new SHA();
        DiffieHellman02 Diff = new DiffieHellman02();
        //dateTimeIV
        string dateTimeIV;
        byte[] dateTimeIv;
        //MD5
        MD5 md5 = new MD5();
        //CHuổi so sánh
        string compare1, compare2;

        /// <summary>
        /// Ket noi toi server
        /// </summary>
        void Connect()
        {
            //IP của server (127.0.0.1)
            IP = new IPEndPoint(IPAddress.Parse("127.0.0.1"), 9999);
            client = new Socket(AddressFamily.InterNetwork, SocketType.Stream,ProtocolType.Tcp);
            try
            {
                client.Connect(IP);
            }
            catch
            {
                MessageBox.Show("Không thể kết nối tới server","Lỗi",MessageBoxButtons.OK,MessageBoxIcon.Error);
                this.Close();
                return;
            }           
            byte[] nhandodai = new byte[1024];
            client.Receive(nhandodai);           
            nhankey = new byte[BitConverter.ToInt32(nhandodai, 0)];           
            client.Receive(nhankey);         
            keypublic = Convert.ToBase64String(nhankey);
            txtkeyserver.Text = keypublic;
            TaoKey();
            Diff.LayKhoaBiMat(nhankey);
            khoabimat = Diff.aes.Key;
            keysecret = Convert.ToBase64String(khoabimat);
            txtFinalKey.Text = keysecret;
            byte[] laydodai = BitConverter.GetBytes(khoapublic.Length);
            client.Send(laydodai);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);               
            Thread listen = new Thread(Receive);
            listen.IsBackground = true;
            listen.Start();
        }

        void TaoKey()
        {
            Diff = new DiffieHellman02();
            khoapublic = Diff.PublicKey;
            keypublic = Convert.ToBase64String(khoapublic);
            txtPublicKey.Text = keypublic;          
        }

        void guilaipublickey()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikeyserver");
            client.Send(batdauguikey);
            byte[] Keypublic = khoapublic;           
            client.Send(Keypublic);
        }

        void guiPublickeyChoServerKhiHetTime()
        {
            byte[] batdauguikey = Encoding.UTF8.GetBytes("guikeytoserver");
            client.Send(batdauguikey);
            byte[] Keypublic = khoapublic;
            client.Send(Keypublic);
        }
        /// <summary>
        /// Close ket noi hien tai
        /// </summary>
        void Close()
        {
            client.Close();
        }

        /// <summary>
        /// Send Message
        /// </summary>
        void Send()
        {
            dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
            string time = dateTimeIV.Substring(0, 16);
            dateTimeIv = Encoding.UTF8.GetBytes(time);
            string a = txtFinalKey.Text.Substring(0, 32);
            byte[] key = Encoding.ASCII.GetBytes(a);
            string s = aes.EncryptString(txtMessage.Text, key, dateTimeIv);
            

            byte[] mahoa = Diff.MaHoaDiffie(nhankey, s);
            byte[] dodai = BitConverter.GetBytes(mahoa.Length);
            byte[] initvector = Diff.IV;
            txtInnitDiffi.Text =Convert.ToBase64String(initvector);
            if (client != null && txtMessage.Text != string.Empty)
            {
                client.Send(dodai);
                client.Send(mahoa);
                client.Send(initvector);
            }            
        }

        /// <summary>
        /// Xuất Message lên listView
        /// </summary>
        /// <param name="s"></param>
        void AddMessage(string s)
        {
            txtViewMessage.Items.Add(new ListViewItem() { Text = "Người lạ: "+ s });
            
        }

        void AddSelfMessage(string s)
        {
            txtViewMessage.Items.Add(new ListViewItem() { Text = "Tôi: " + s });
            
        }
        void MessageHeTHong(string s)
        {
            txtViewMessage.Items.Add(new ListViewItem() { Text = "Hệ Thống : " + s });
        }
        /// <summary>
        /// Receive Message
        /// </summary>
        void Receive()
        {       
            try
            {
               c: while (true)//luôn luôn nhận
                {
                    data = new byte[1024];
                    client.Receive(data);     
                    
                    if (string.Equals(Encoding.UTF8.GetString(data), "guikey", StringComparison.InvariantCultureIgnoreCase))
                    {                                               
                        txtkeyserver.Clear();
                        txtFinalKey.Clear();
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);                        
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        txtkeyserver.Text = keypublic;
                        TaoKey();
                        Diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = Diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        txtFinalKey.Text = keysecret;
                        nhankey = nhankeydadoi;
                        guilaipublickey();
                    }
                    else if (string.Equals(Encoding.UTF8.GetString(data), "guikeytoclient", StringComparison.InvariantCultureIgnoreCase))
                    {
                        txtkeyserver.Clear();
                        txtFinalKey.Clear();
                        nhankeydadoi = new byte[140];
                        client.Receive(nhankeydadoi);
                        keypublic = Convert.ToBase64String(nhankeydadoi);
                        txtkeyserver.Text = keypublic;                        
                        Diff.LayKhoaBiMat(nhankeydadoi);
                        khoabimat = Diff.aes.Key;
                        keysecret = Convert.ToBase64String(khoabimat);
                        txtFinalKey.Text = keysecret;
                        nhankey = nhankeydadoi;                       
                    }
                    else
                    {
                        dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
                        string time = dateTimeIV.Substring(0, 16);
                        dateTimeIv = Encoding.UTF8.GetBytes(time);
                       
                        tinnhan = new byte[BitConverter.ToInt32(data, 0)];                       
                        client.Receive(tinnhan);
                        byte[] nhanvector = new byte[16];
                        client.Receive(nhanvector);                       
                        string message = Diff.GiaiMaDiffie(nhankey, tinnhan, nhanvector);
                        string a = txtFinalKey.Text.Substring(0, 32);
                        byte[] key = Encoding.ASCII.GetBytes(a);
                        string s = aes.DecryptString(message, key, dateTimeIv);
                        foreach (char c in s)
                        {
                            if (c.ToString() == ";")
                            {
                                string[] tokens = s.Trim().Split(';');
                                compare1 = tokens[1];
                                compare2 = md5.maHoaMd5(tokens[0]);
                                if (compare1 != compare2)
                                {
                                    AddMessage(tokens[0]);
                                    MessageHeTHong("chuỗi này đã bị thay đổi vì 2 chuỗi mã hóa khác nhau :");
                                    MessageHeTHong("Chuỗi mã hóa trước khi gửi :" + compare1);
                                    MessageHeTHong("chuỗi mã hóa sau khi mã hóa tin nhận :" + compare2);
                                    goto c;
                                }

                            }

                        }
                        AddMessage(s);
                    }                    
                }
            }

            catch(Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            
        }

        /// <summary>
        /// phân mảnh
        /// </summary>
        byte[] Serialize(object obj)
        {
            MemoryStream stream = new MemoryStream();
            BinaryFormatter formatter = new BinaryFormatter();

            formatter.Serialize(stream, obj);
            return stream.ToArray();
        }

        /// <summary>
        /// gom mảnh
        /// </summary>
        /// <returns></returns>
        object Deserialize(byte[] data)
        {
            MemoryStream stream = new MemoryStream(data);
            BinaryFormatter formatter = new BinaryFormatter();
            return formatter.Deserialize(stream);            
        }
                

        private void btnSendError_Click(object sender, EventArgs e)
        {

        }

        /// <summary>
        /// Đóng kết nối khi đóng form
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void Client_FormClosed(object sender, FormClosedEventArgs e)
        {
            Close();
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            timer1.Stop();
            Send();
            AddSelfMessage(txtMessage.Text);
            txtMessage.Clear();
            timer1.Start();
            sec = 21;
            timer1.Start();
           
        }

        Aes_EcbEncrypt AES = new Aes_EcbEncrypt();
    

        private void txtViewMessage_SelectedIndexChanged(object sender, EventArgs e)
        {

        }

        private void txtViewMessage_KeyUp(object sender, KeyEventArgs e)
        {
            if (sender != txtViewMessage) return;

            if (e.Control && e.KeyCode == Keys.C)
                CopySelectedValuesToClipboard();
        }
        private void CopySelectedValuesToClipboard()
        {
            var builder = new StringBuilder();
            foreach (ListViewItem item in txtViewMessage.SelectedItems)
                builder.AppendLine(item.SubItems[0].Text);

            Clipboard.SetText(builder.ToString());
        }
        //thêm random
        private static string RandomString(string baseString, string character, int position)
        {
            var sb = new StringBuilder(baseString);

            sb.Insert(position, character);

            return sb.ToString();
        }

        private void Client_Load(object sender, EventArgs e)
        {
            TimeSession.Start();
        }

        private void btnSendNoise_Click(object sender, EventArgs e)
        {
            AddSelfMessage(txtMessage.Text);
            //tạo chuỗi mã hóa tin nhắn ban đầu + hash time
            string s = md5.maHoaMd5(txtMessage.Text);
            dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
            string Mahoa_time = s + ";" + dateTimeIV;

            //tạo các chữ random để chèn vào
            char[] chars = "abcdefghijklmnopqrstuvwxyz1234567890".ToCharArray();
            Random r = new Random();
            int i = r.Next(chars.Length);
            int vitri = r.Next(0, txtMessage.TextLength);

            //Chuỗi Đã thay đổi
            txtMessage.Text = RandomString(txtMessage.Text, chars[i].ToString(), vitri) + ";" + Mahoa_time;
            Send();
            
            TimeSession.Stop();
            sec = 21;
            TimeSession.Start();
        }

        int sec = 20;
        private void timer1_Tick(object sender, EventArgs e)
        {
            lbltime.Visible = true;
            lbltime.Text = sec.ToString();
            if (sec < 10)
            {
                lbltime.Text = "0" + sec.ToString();
            }
            if (sec <= 0)
            {
                timer1.Stop();
                txtkeyserver.Clear();
                txtFinalKey.Clear();
                TaoKey();
                guiPublickeyChoServerKhiHetTime();
                laptime();
            }
            sec--;  
        }

        private void TimeSession_Tick(object sender, EventArgs e)
        {
            dateTimeIV = md5.maHoaMd5(DateTime.Now.ToString());
            string time = dateTimeIV.Substring(0, 16);
            dateTimeIv = Encoding.UTF8.GetBytes(time);
            txtInitVector.Text = Encoding.UTF8.GetString(dateTimeIv);
        }

        private void laptime()
        {
            sec = 21;
            timer1 = new System.Windows.Forms.Timer();
            timer1.Tick += new EventHandler(timer1_Tick);
            timer1.Interval = 1000;
            timer1.Start();
        }
    }
}

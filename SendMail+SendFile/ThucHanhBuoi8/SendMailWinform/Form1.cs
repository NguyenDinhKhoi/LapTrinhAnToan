using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net.Mail;
using System.Net;
using System.IO;

namespace SendMailWinform
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        MailMessage message;
        string duongdan = "";

        private void SendCompletedCallback(object sender, AsyncCompletedEventArgs e)
        {
            if (e.Cancelled)
            {
                MessageBox.Show("Đã dừng việc gửi mail!");
                lbltinhtrang.Visible = false;
                btnSend.Enabled = true;
            }
            if (e.Error != null)
            {
                MessageBox.Show("Gửi mail thất bại!");
                lbltinhtrang.Visible = false;
                btnSend.Enabled = true;
            }
            else
            {
                MessageBox.Show("Gửi mail thành công");
                lbltinhtrang.Visible = false;
                btnSend.Enabled = true;
            }

            ((MailMessage)e.UserState).Dispose();//Dispose
        }

        private void btnSend_Click(object sender, EventArgs e)
        {
            SmtpClient mailclient = new SmtpClient("smtp.gmail.com", 587);
            mailclient.EnableSsl = true;
            mailclient.Credentials = new NetworkCredential("khoiyugi97@gmail.com","123talavip");
            message = new MailMessage("khoiyugi97@gmail.com", txbTo.Text);
            message.Subject = txbTieude.Text;
            message.Body = rtbNoidung.Text;
            if (duongdan != null)
            {
                message.Attachments.Add(new System.Net.Mail.Attachment(duongdan));
            }      
            mailclient.SendCompleted += new SendCompletedEventHandler(SendCompletedCallback);
            lbltinhtrang.Visible = true;
            lbltinhtrang.Text = "Đang gửi mail... vui lòng chờ!";
            btnSend.Enabled = false;
            mailclient.SendAsync(message, message);                    
        }

        private void btndinhkem_Click(object sender, EventArgs e)
        {
            OpenFileDialog file = new OpenFileDialog();
            file.InitialDirectory = @"C:\";
            file.Title = "Tìm file";

            file.CheckFileExists = true;
            file.CheckPathExists = true;

            file.DefaultExt = "txt";
            file.Filter = "All file (*.*)|*.*";            
            file.RestoreDirectory = true;

            file.ReadOnlyChecked = true;
            file.ShowReadOnly = true;

            if (file.ShowDialog() == DialogResult.OK)
            {
                duongdan = file.FileName;
            }
            message = new MailMessage();
            lbltaptin.Visible = true;
            lbltaptin.Text = Path.GetFileName(duongdan);           
        }
    }
}

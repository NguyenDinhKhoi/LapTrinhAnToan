﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Linq;

namespace UserPassHashCode
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }
        
        SHA sha1 = new SHA();
        int i=0;
        int r = 0;

        String[] Login;

        public int I { get => i; set => i = value; }
        public int R { get => r; set => r = value; }

        private void Form1_Load(object sender, EventArgs e)
        {
            Login = new string[100];

        }

        private void btnSave_Click(object sender, EventArgs e)
        {
           
            if (txtUser.Text != "" && txtPassWord.Text != "")
            {
                for (i =r ; i < Login.Length; i++)
                {
                    
                        if (txtUser.Text != Login[i])
                        {

                            Login[i] = sha1.SHA1(txtUser.Text);
                            Login[i + 1] = sha1.SHA1(txtPassWord.Text);
                            MessageBox.Show("Saved Password");
                            txtUser.Clear();
                            txtPassWord.Clear();
                            r=r+2;
                            break;

                        }
                        else
                        {
                            MessageBox.Show("User da ton tai");
                            break;

                        }
                    }
                }
                
                }
            
        

        private void txtUser_TextChanged(object sender, EventArgs e)
        {
            if (txtPassWord.Text != "")
            {
                btnLogin.Enabled = true;
                btnSave.Enabled = true;
            }
        }

        private void txtPassWord_TextChanged(object sender, EventArgs e)
        {
            if (txtUser.Text != "")
            {
                btnLogin.Enabled = true;
                btnSave.Enabled = true;
            }
        }

        private void btnLogin_Click(object sender, EventArgs e)
        {
            for (int i = 0; i < Login.Length; i++)
            {
               
                    if (sha1.SHA1(txtUser.Text) == Login[i] && sha1.SHA1(txtPassWord.Text) == Login[i+1])
                    {
                        MessageBox.Show("Accepted login");
                        break;
                    }
                    else
                    {
                        MessageBox.Show("Failed login");
                        break;
                    }
                
            }
        }
    }
}
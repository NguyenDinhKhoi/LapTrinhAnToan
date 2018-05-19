namespace Server
{
    partial class Server
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.txtViewMessage = new System.Windows.Forms.ListView();
            this.txtKey = new System.Windows.Forms.TextBox();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.btnSend = new DevComponents.DotNetBar.ButtonX();
            this.btnSendNoise = new DevComponents.DotNetBar.ButtonItem();
            this.txtMessage = new System.Windows.Forms.TextBox();
            this.lbKey = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.txbSecretkey = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.lbltime = new System.Windows.Forms.Label();
            this.timer1 = new System.Windows.Forms.Timer(this.components);
            this.label2 = new System.Windows.Forms.Label();
            this.txtkeyclient = new System.Windows.Forms.TextBox();
            this.groupBox2.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.txtViewMessage);
            this.groupBox2.Location = new System.Drawing.Point(26, 12);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(552, 330);
            this.groupBox2.TabIndex = 28;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "View";
            // 
            // txtViewMessage
            // 
            this.txtViewMessage.BackColor = System.Drawing.SystemColors.Control;
            this.txtViewMessage.Location = new System.Drawing.Point(7, 13);
            this.txtViewMessage.Name = "txtViewMessage";
            this.txtViewMessage.Size = new System.Drawing.Size(539, 311);
            this.txtViewMessage.TabIndex = 0;
            this.txtViewMessage.UseCompatibleStateImageBehavior = false;
            this.txtViewMessage.View = System.Windows.Forms.View.List;
            this.txtViewMessage.KeyUp += new System.Windows.Forms.KeyEventHandler(this.txtViewMessage_KeyUp);
            // 
            // txtKey
            // 
            this.txtKey.Location = new System.Drawing.Point(26, 441);
            this.txtKey.Name = "txtKey";
            this.txtKey.Size = new System.Drawing.Size(436, 20);
            this.txtKey.TabIndex = 26;
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.btnSend);
            this.groupBox1.Location = new System.Drawing.Point(601, 361);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(87, 100);
            this.groupBox1.TabIndex = 25;
            this.groupBox1.TabStop = false;
            // 
            // btnSend
            // 
            this.btnSend.AccessibleRole = System.Windows.Forms.AccessibleRole.PushButton;
            this.btnSend.ColorTable = DevComponents.DotNetBar.eButtonColor.OrangeWithBackground;
            this.btnSend.Location = new System.Drawing.Point(6, 19);
            this.btnSend.Name = "btnSend";
            this.btnSend.Size = new System.Drawing.Size(75, 62);
            this.btnSend.Style = DevComponents.DotNetBar.eDotNetBarStyle.StyleManagerControlled;
            this.btnSend.SubItems.AddRange(new DevComponents.DotNetBar.BaseItem[] {
            this.btnSendNoise});
            this.btnSend.TabIndex = 0;
            this.btnSend.Text = "Send";
            this.btnSend.Click += new System.EventHandler(this.btnSend_Click);
            // 
            // btnSendNoise
            // 
            this.btnSendNoise.GlobalItem = false;
            this.btnSendNoise.Name = "btnSendNoise";
            this.btnSendNoise.Text = "Send+Noise";
            this.btnSendNoise.Click += new System.EventHandler(this.btnSendNoise_Click);
            // 
            // txtMessage
            // 
            this.txtMessage.Location = new System.Drawing.Point(26, 361);
            this.txtMessage.Multiline = true;
            this.txtMessage.Name = "txtMessage";
            this.txtMessage.Size = new System.Drawing.Size(538, 55);
            this.txtMessage.TabIndex = 24;
            // 
            // lbKey
            // 
            this.lbKey.AutoSize = true;
            this.lbKey.ForeColor = System.Drawing.Color.DarkRed;
            this.lbKey.Location = new System.Drawing.Point(30, 425);
            this.lbKey.Name = "lbKey";
            this.lbKey.Size = new System.Drawing.Size(116, 13);
            this.lbKey.TabIndex = 29;
            this.lbKey.Text = "Public Key của server :";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.ForeColor = System.Drawing.Color.DarkRed;
            this.label1.Location = new System.Drawing.Point(30, 520);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(56, 13);
            this.label1.TabIndex = 31;
            this.label1.Text = "Final Key :";
            // 
            // txbSecretkey
            // 
            this.txbSecretkey.Location = new System.Drawing.Point(26, 536);
            this.txbSecretkey.Name = "txbSecretkey";
            this.txbSecretkey.Size = new System.Drawing.Size(436, 20);
            this.txbSecretkey.TabIndex = 30;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(23, 345);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(56, 13);
            this.label4.TabIndex = 34;
            this.label4.Text = "Message :";
            // 
            // groupBox3
            // 
            this.groupBox3.Controls.Add(this.lbltime);
            this.groupBox3.Location = new System.Drawing.Point(593, 27);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(130, 90);
            this.groupBox3.TabIndex = 35;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Session Time";
            // 
            // lbltime
            // 
            this.lbltime.AutoSize = true;
            this.lbltime.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lbltime.Location = new System.Drawing.Point(50, 37);
            this.lbltime.Name = "lbltime";
            this.lbltime.Size = new System.Drawing.Size(61, 20);
            this.lbltime.TabIndex = 0;
            this.lbltime.Text = "lbltime";
            this.lbltime.Visible = false;
            // 
            // timer1
            // 
            this.timer1.Interval = 1000;
            this.timer1.Tick += new System.EventHandler(this.timer1_Tick);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.ForeColor = System.Drawing.Color.DarkRed;
            this.label2.Location = new System.Drawing.Point(30, 471);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(112, 13);
            this.label2.TabIndex = 37;
            this.label2.Text = "Public Key của client :";
            // 
            // txtkeyclient
            // 
            this.txtkeyclient.Location = new System.Drawing.Point(26, 487);
            this.txtkeyclient.Name = "txtkeyclient";
            this.txtkeyclient.Size = new System.Drawing.Size(436, 20);
            this.txtkeyclient.TabIndex = 36;
            // 
            // Server
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.ClientSize = new System.Drawing.Size(746, 577);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.txtkeyclient);
            this.Controls.Add(this.groupBox3);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.txbSecretkey);
            this.Controls.Add(this.lbKey);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.txtKey);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.txtMessage);
            this.Name = "Server";
            this.Text = "Server";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.Server_FormClosed);
            this.groupBox2.ResumeLayout(false);
            this.groupBox1.ResumeLayout(false);
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.ListView txtViewMessage;
        private System.Windows.Forms.TextBox txtKey;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.TextBox txtMessage;
        private DevComponents.DotNetBar.ButtonX btnSend;
        private DevComponents.DotNetBar.ButtonItem btnSendNoise;
        private System.Windows.Forms.Label lbKey;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txbSecretkey;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.GroupBox groupBox3;
        private System.Windows.Forms.Label lbltime;
        private System.Windows.Forms.Timer timer1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtkeyclient;
    }
}


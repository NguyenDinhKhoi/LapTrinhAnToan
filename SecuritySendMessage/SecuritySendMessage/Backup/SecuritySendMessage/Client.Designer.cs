namespace SecuritySendMessage
{
    partial class Client
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
            this.txtViewMessage = new System.Windows.Forms.ListView();
            this.txtMessage = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.btnSend = new DevComponents.DotNetBar.ButtonX();
            this.btnSendNoise = new DevComponents.DotNetBar.ButtonItem();
            this.lbKey = new System.Windows.Forms.Label();
            this.txtPublicKey = new System.Windows.Forms.TextBox();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.btnSendError = new DevComponents.DotNetBar.ButtonItem();
            this.btnDecrypt = new DevComponents.DotNetBar.ButtonItem();
            this.label2 = new System.Windows.Forms.Label();
            this.txtFinalKey = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.txtkeyserver = new System.Windows.Forms.TextBox();
            this.groupBox1.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // txtViewMessage
            // 
            this.txtViewMessage.BackColor = System.Drawing.SystemColors.Control;
            this.txtViewMessage.Location = new System.Drawing.Point(6, 16);
            this.txtViewMessage.Name = "txtViewMessage";
            this.txtViewMessage.Size = new System.Drawing.Size(539, 311);
            this.txtViewMessage.TabIndex = 0;
            this.txtViewMessage.UseCompatibleStateImageBehavior = false;
            this.txtViewMessage.View = System.Windows.Forms.View.List;
            this.txtViewMessage.SelectedIndexChanged += new System.EventHandler(this.txtViewMessage_SelectedIndexChanged);
            this.txtViewMessage.KeyUp += new System.Windows.Forms.KeyEventHandler(this.txtViewMessage_KeyUp);
            // 
            // txtMessage
            // 
            this.txtMessage.Location = new System.Drawing.Point(12, 351);
            this.txtMessage.Multiline = true;
            this.txtMessage.Name = "txtMessage";
            this.txtMessage.Size = new System.Drawing.Size(538, 55);
            this.txtMessage.TabIndex = 1;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(15, 335);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(56, 13);
            this.label4.TabIndex = 18;
            this.label4.Text = "Message :";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.btnSend);
            this.groupBox1.Location = new System.Drawing.Point(587, 351);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(87, 100);
            this.groupBox1.TabIndex = 19;
            this.groupBox1.TabStop = false;
            // 
            // btnSend
            // 
            this.btnSend.AccessibleRole = System.Windows.Forms.AccessibleRole.PushButton;
            this.btnSend.ColorTable = DevComponents.DotNetBar.eButtonColor.OrangeWithBackground;
            this.btnSend.Location = new System.Drawing.Point(6, 28);
            this.btnSend.Name = "btnSend";
            this.btnSend.Size = new System.Drawing.Size(75, 55);
            this.btnSend.Style = DevComponents.DotNetBar.eDotNetBarStyle.StyleManagerControlled;
            this.btnSend.SubItems.AddRange(new DevComponents.DotNetBar.BaseItem[] {
            this.btnSendNoise});
            this.btnSend.TabIndex = 2;
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
            // lbKey
            // 
            this.lbKey.AutoSize = true;
            this.lbKey.ForeColor = System.Drawing.Color.DarkRed;
            this.lbKey.Location = new System.Drawing.Point(15, 415);
            this.lbKey.Name = "lbKey";
            this.lbKey.Size = new System.Drawing.Size(112, 13);
            this.lbKey.TabIndex = 21;
            this.lbKey.Text = "Public Key của client :";
            // 
            // txtPublicKey
            // 
            this.txtPublicKey.Location = new System.Drawing.Point(12, 431);
            this.txtPublicKey.Name = "txtPublicKey";
            this.txtPublicKey.Size = new System.Drawing.Size(436, 20);
            this.txtPublicKey.TabIndex = 20;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.txtViewMessage);
            this.groupBox2.Location = new System.Drawing.Point(12, 2);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(552, 330);
            this.groupBox2.TabIndex = 23;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "View";
            // 
            // btnSendError
            // 
            this.btnSendError.GlobalItem = false;
            this.btnSendError.Name = "btnSendError";
            this.btnSendError.Text = "btnSendError";
            this.btnSendError.Click += new System.EventHandler(this.btnSendError_Click);
            // 
            // btnDecrypt
            // 
            this.btnDecrypt.GlobalItem = false;
            this.btnDecrypt.Name = "btnDecrypt";
            this.btnDecrypt.Text = "Decrypt";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.ForeColor = System.Drawing.Color.DarkRed;
            this.label2.Location = new System.Drawing.Point(15, 503);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(56, 13);
            this.label2.TabIndex = 27;
            this.label2.Text = "Final Key :";
            // 
            // txtFinalKey
            // 
            this.txtFinalKey.Location = new System.Drawing.Point(12, 519);
            this.txtFinalKey.Name = "txtFinalKey";
            this.txtFinalKey.Size = new System.Drawing.Size(436, 20);
            this.txtFinalKey.TabIndex = 26;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.ForeColor = System.Drawing.Color.DarkRed;
            this.label1.Location = new System.Drawing.Point(15, 458);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(116, 13);
            this.label1.TabIndex = 29;
            this.label1.Text = "Public Key của server :";
            // 
            // txtkeyserver
            // 
            this.txtkeyserver.Location = new System.Drawing.Point(12, 474);
            this.txtkeyserver.Name = "txtkeyserver";
            this.txtkeyserver.Size = new System.Drawing.Size(436, 20);
            this.txtkeyserver.TabIndex = 28;
            // 
            // Client
            // 
            this.AcceptButton = this.btnSend;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.ClientSize = new System.Drawing.Size(699, 560);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.txtkeyserver);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.txtFinalKey);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.lbKey);
            this.Controls.Add(this.txtPublicKey);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.txtMessage);
            this.Name = "Client";
            this.Text = "Client";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.Client_FormClosed);
            this.Load += new System.EventHandler(this.Client_Load);
            this.groupBox1.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.ListView txtViewMessage;
        private System.Windows.Forms.TextBox txtMessage;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label lbKey;
        private System.Windows.Forms.TextBox txtPublicKey;
        private System.Windows.Forms.GroupBox groupBox2;
        private DevComponents.DotNetBar.ButtonX btnSend;
        private DevComponents.DotNetBar.ButtonItem btnSendError;
        private DevComponents.DotNetBar.ButtonItem btnDecrypt;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtFinalKey;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtkeyserver;
        private DevComponents.DotNetBar.ButtonItem btnSendNoise;
    }
}


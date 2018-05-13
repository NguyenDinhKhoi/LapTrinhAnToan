namespace SendMailWinform
{
    partial class Form1
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
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.txbTo = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.txbTieude = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.rtbNoidung = new System.Windows.Forms.RichTextBox();
            this.btnSend = new System.Windows.Forms.Button();
            this.lbltinhtrang = new System.Windows.Forms.Label();
            this.btndinhkem = new System.Windows.Forms.Button();
            this.lbltaptin = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Font = new System.Drawing.Font("Microsoft Sans Serif", 15.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label2.Location = new System.Drawing.Point(138, 9);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(98, 25);
            this.label2.TabIndex = 0;
            this.label2.Text = "Gửi mail";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(23, 46);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(27, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "Đến";
            // 
            // txbTo
            // 
            this.txbTo.Location = new System.Drawing.Point(81, 43);
            this.txbTo.Name = "txbTo";
            this.txbTo.Size = new System.Drawing.Size(236, 20);
            this.txbTo.TabIndex = 2;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(23, 80);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(44, 13);
            this.label3.TabIndex = 3;
            this.label3.Text = "Tiêu đề";
            // 
            // txbTieude
            // 
            this.txbTieude.Location = new System.Drawing.Point(81, 77);
            this.txbTieude.Name = "txbTieude";
            this.txbTieude.Size = new System.Drawing.Size(236, 20);
            this.txbTieude.TabIndex = 4;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(23, 118);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(50, 13);
            this.label4.TabIndex = 5;
            this.label4.Text = "Nội dung";
            // 
            // rtbNoidung
            // 
            this.rtbNoidung.Location = new System.Drawing.Point(79, 115);
            this.rtbNoidung.Name = "rtbNoidung";
            this.rtbNoidung.Size = new System.Drawing.Size(311, 120);
            this.rtbNoidung.TabIndex = 6;
            this.rtbNoidung.Text = "";
            // 
            // btnSend
            // 
            this.btnSend.Location = new System.Drawing.Point(315, 302);
            this.btnSend.Name = "btnSend";
            this.btnSend.Size = new System.Drawing.Size(75, 23);
            this.btnSend.TabIndex = 7;
            this.btnSend.Text = "Gửi";
            this.btnSend.UseVisualStyleBackColor = true;
            this.btnSend.Click += new System.EventHandler(this.btnSend_Click);
            // 
            // lbltinhtrang
            // 
            this.lbltinhtrang.AutoSize = true;
            this.lbltinhtrang.Location = new System.Drawing.Point(140, 307);
            this.lbltinhtrang.Name = "lbltinhtrang";
            this.lbltinhtrang.Size = new System.Drawing.Size(58, 13);
            this.lbltinhtrang.TabIndex = 8;
            this.lbltinhtrang.Text = "lbltinhtrang";
            this.lbltinhtrang.Visible = false;
            // 
            // btndinhkem
            // 
            this.btndinhkem.Location = new System.Drawing.Point(201, 241);
            this.btndinhkem.Name = "btndinhkem";
            this.btndinhkem.Size = new System.Drawing.Size(75, 23);
            this.btndinhkem.TabIndex = 9;
            this.btndinhkem.Text = "Đính kèm";
            this.btndinhkem.UseVisualStyleBackColor = true;
            this.btndinhkem.Click += new System.EventHandler(this.btndinhkem_Click);
            // 
            // lbltaptin
            // 
            this.lbltaptin.AutoSize = true;
            this.lbltaptin.Location = new System.Drawing.Point(297, 246);
            this.lbltaptin.Name = "lbltaptin";
            this.lbltaptin.Size = new System.Drawing.Size(43, 13);
            this.lbltaptin.TabIndex = 10;
            this.lbltaptin.Text = "lbltaptin";
            this.lbltaptin.Visible = false;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(429, 344);
            this.Controls.Add(this.lbltaptin);
            this.Controls.Add(this.btndinhkem);
            this.Controls.Add(this.lbltinhtrang);
            this.Controls.Add(this.btnSend);
            this.Controls.Add(this.rtbNoidung);
            this.Controls.Add(this.label4);
            this.Controls.Add(this.txbTieude);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.txbTo);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.label2);
            this.Name = "Form1";
            this.Text = "Gửi mail";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txbTo;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txbTieude;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.RichTextBox rtbNoidung;
        private System.Windows.Forms.Button btnSend;
        private System.Windows.Forms.Label lbltinhtrang;
        private System.Windows.Forms.Button btndinhkem;
        private System.Windows.Forms.Label lbltaptin;
    }
}


const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  host : 'smtp.gmail.com',
  port: 465,
  auth: {
    user: 'emptybags06@gmail.com',    
    pass: 'Felix@2005'             
  }
});

function sendOTP(email) {
  const otp = Math.floor(1000 + Math.random() * 9000);

  const mailOptions = {
    from: 'emptybags06@gmail.com',
    to: email,
    subject: 'OTP Verification',
    text: `Your OTP is: ${otp}`
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending OTP:', error);
    } else {
      console.log('OTP sent successfully.');
      return otp;
    }
  });
}
const recipientEmail = "727722eucs097@gmail.com"; 
sendOTP(recipientEmail);

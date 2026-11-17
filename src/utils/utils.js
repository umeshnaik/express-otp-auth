import crypto from "crypto";

export const generateOtp = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

export const getOtpHtml = (otp) => {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <title>OTP Verification</title>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Your OTP is: <strong>${otp}</strong></p>
        <p>Please use this OTP to complete your verification process.</p>
      </body>
    </html>
  `;
};

export const hashOtp = (otp) => {
  return crypto.createHash("sha256").update(otp).digest("hex");
};

import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";

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

export const hashKey = (key) => {
  return crypto.createHash("sha256").update(key).digest("hex");
};

export const generateJwtToken = (payload, expiresIn) => {
  return jwt.sign(payload, config.JWT_SECRET, { expiresIn });
};

export const verifyJwtToken = (token) => {
  try {
    return jwt.verify(token, config.JWT_SECRET);
  } catch (error) {
    return null;
  }
};

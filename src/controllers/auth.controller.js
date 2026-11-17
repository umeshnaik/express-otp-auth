import UserModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import SessionModel from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import { otpModel } from "../models/otp.model.js";
import { generateOtp, getOtpHtml } from "../utils/utils.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  const isAlreadyRegistered = await UserModel.findOne({
    $or: [{ username }, { email }],
  });

  if (isAlreadyRegistered) {
    return res.status(409).json({
      message: "Username or email already exists",
    });
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const user = await UserModel.create({
    username,
    email,
    password: hashedPassword,
  });

  const otp = generateOtp();
  const html = getOtpHtml(otp);

  const otpHash = hashOtp(otp);

  await otpModel.create({
    email,
    user: user._id,
    otpHash,
  });

  await sendEmail(email, "OTP Verification", `Your OTP is: ${otp}`, html);

  res.status(201).json({
    message: "User registered successfully",
    user: {
      username: user.username,
      email: user.email,
      verified: user.verified,
    },
  });
};

export const login = async (req, res) => {
  const { email, password } = req.body;
  const user = await UserModel.findOne({ email });

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (!user.verified) {
    return res
      .status(403)
      .json({ message: "User not verified. Please verify your email." });
  }

  const hashedPassword = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const isPasswordValid = hashedPassword === user.password;
  if (!isPasswordValid) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const refreshToken = jwt.sign(
    {
      id: user._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "7d",
    },
  );

  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  const session = await SessionModel.create({
    user: user._id,
    refreshTokenHash: refreshTokenHash,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
  });

  const accessToken = jwt.sign(
    {
      id: user._id,
      sessionId: session._id,
    },
    config.JWT_SECRET,
    {
      expiresIn: "15m",
    },
  );

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  res.status(200).json({
    message: "User logged in successfully",
    user: {
      username: user.username,
      email: user.email,
    },
    accessToken,
  });
};

export const getMe = async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, config.JWT_SECRET);
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
  const user = await UserModel.findById(decoded.id);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  res.status(200).json({
    message: "User fetched successfully",
    user: {
      username: user.username,
      email: user.email,
    },
  });
};

export const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    const user = await UserModel.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");

    const session = await SessionModel.findOne({
      user: user._id,
      refreshTokenHash: refreshTokenHash,
      revoke: false,
    });

    if (!session) {
      return res.status(400).json({ message: "Invalid refresh token" });
    }

    const newAccessToken = jwt.sign(
      {
        id: user._id,
      },
      config.JWT_SECRET,
      {
        expiresIn: "15m",
      },
    );

    const newRefreshToken = jwt.sign(
      {
        id: user._id,
      },
      config.JWT_SECRET,
      {
        expiresIn: "7d",
      },
    );

    const newRefreshTokenHash = crypto
      .createHash("sha256")
      .update(newRefreshToken)
      .digest("hex");

    session.refreshTokenHash = newRefreshTokenHash;
    await session.save();

    res.cookie("refreshToken", newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      message: "Token refreshed successfully",
      accessToken: newAccessToken,
    });
  } catch (error) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
};

export const logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const refreshTokenHash = crypto
      .createHash("sha256")
      .update(refreshToken)
      .digest("hex");
    const session = await SessionModel.findOne({
      refreshTokenHash: refreshTokenHash,
      revoke: false,
    });
    if (!session) {
      return res.status(400).json({ message: "Invalid refresh token" });
    }

    session.revoke = true;
    await session.save();

    res.clearCookie("refreshToken");
    res.status(200).json({ message: "Logged out successfully" });
  } catch (error) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
};

export const logoutAll = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;
  if (!refreshToken) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    await SessionModel.updateMany(
      {
        user: decoded.id,
        revoke: false,
      },
      {
        revoke: true,
      },
    );
    res.clearCookie("refreshToken");
    res
      .status(200)
      .json({ message: "Logged out of all sessions successfully" });
  } catch (error) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
};

export const verifyEmail = async (req, res) => {
  const { email, otp } = req.body;
  const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

  const otpRecord = await otpModel.findOne({ email, otpHash });
  if (!otpRecord) {
    return res.status(400).json({ message: "Invalid OTP" });
  }

  const user = await UserModel.findOne({ email });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.verified = true;
  await user.save();

  await otpModel.deleteMany({
    user: otpRecord.user,
  });

  res.status(200).json({
    message: "Email verified successfully",
    user: {
      username: user.username,
      email: user.email,
      verified: user.verified,
    },
  });
};

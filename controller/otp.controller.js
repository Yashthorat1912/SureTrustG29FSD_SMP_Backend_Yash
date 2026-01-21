import dotenv from "dotenv";
import { OTP } from "../schemas/otp.schema.js";
import UserSchema from "../schemas/User.schema.js";
import bcrypt from "bcryptjs";
import SibApiV3Sdk from "sib-api-v3-sdk";

dotenv.config();

const salt = bcrypt.genSaltSync(10);

/* =========================
   BREVO CONFIGURATION
========================= */

const client = SibApiV3Sdk.ApiClient.instance;
client.authentications["api-key"].apiKey = process.env.BREVO_API_KEY;

const tranEmailApi = new SibApiV3Sdk.TransactionalEmailsApi();

/* =========================
   CREATE OTP
========================= */

export const createOTP = async (req, res) => {
  try {
    console.log("OTP request received");

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await UserSchema.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const generatedOTP = Math.floor(100000 + Math.random() * 900000).toString();

    await OTP.create({
      email,
      otp: generatedOTP,
      createdAt: Date.now(),
      is_expired: false,
    });

    // ✅ SEND OTP USING BREVO (EMAIL FROM ENV)
    await tranEmailApi.sendTransacEmail({
      sender: {
        email: process.env.mail_id, // 👈 FROM ENV
        name: "OTP Service",
      },
      to: [{ email }],
      subject: "Your OTP Code",
      htmlContent: `
        <div style="font-family: Arial">
          <h2>Your OTP Code</h2>
          <h1 style="color:#4CAF50">${generatedOTP}</h1>
          <p>This OTP is valid for 5 minutes.</p>
        </div>
      `,
    });

    console.log("OTP email sent successfully");

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (error) {
    console.error("Error creating OTP:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

/* =========================
   CHANGE PASSWORD WITH OTP
========================= */

export const changePasswordWithOTP = async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const otpEntry = await OTP.findOne({ email, otp }).sort({ createdAt: -1 });
    if (!otpEntry) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    if (otpEntry.is_expired === true) {
      return res.status(400).json({ message: "OTP has expired" });
    }

    const user = await UserSchema.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const hashedPassword = bcrypt.hashSync(newPassword, salt);
    user.password = hashedPassword;
    await user.save();

    await OTP.deleteMany({ email });

    res.status(200).json({ message: "Password changed successfully" });
  } catch (error) {
    console.error("Error changing password with OTP:", error);
    res.status(500).json({ message: "Internal server error" });
  }
};

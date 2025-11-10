// ===== Dependencies =====
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { google } from "googleapis";
import fs from "fs";

// ===== Config =====
dotenv.config();
const app = express();
const PORT = process.env.PORT || 8000;

// ===== Middleware =====
app.use(cors());
app.use(express.json());

// ===== MongoDB Connection =====
mongoose
  .connect(process.env.MONGODB_URI, { dbName: process.env.DB_NAME })
  .then(() => {
    console.log("✅ MongoDB Connected");
    createDefaultUsers(); // Run after successful connection
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ===== Nodemailer Setup =====
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ===== Google Drive Setup =====
let key = {};
try {
  key = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON || "{}");
} catch (e) {
  console.error("❌ Invalid GOOGLE_SERVICE_ACCOUNT_JSON format");
}

const auth = new google.auth.GoogleAuth({
  credentials: key,
  scopes: ["https://www.googleapis.com/auth/drive"],
});
const drive = google.drive({ version: "v3", auth });

const PUBLIC_FOLDER_ID = process.env.PUBLIC_FOLDER_ID;
const PRIVATE_FOLDER_ID = process.env.PRIVATE_FOLDER_ID;

// ===== MongoDB Schemas =====
const contactSchema = new mongoose.Schema({
  name: String,
  mail: String,
  message: String,
  createdAt: { type: Date, default: Date.now },
});
const Contact = mongoose.model("Contact", contactSchema);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  folderAccess: { type: String, enum: ["public", "private"], default: "public" },
  sole: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

// ===== Contact API =====
app.post("/contact", async (req, res) => {
  try {
    const { name, mail, message } = req.body;
    if (!name || !mail || !message)
      return res.status(400).json({ success: false, message: "All fields required" });

    const contact = new Contact({ name, mail, message });
    await contact.save();

    // Notify admin
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `New Message from ${name}`,
      text: `Name: ${name}\nEmail: ${mail}\nMessage: ${message}`,
    });

    // Acknowledge sender
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: mail,
      subject: `Thanks for reaching out, ${name}!`,
      text: `Hi ${name},\n\nYour message has been received. We'll get back to you soon.\n\n– Team`,
    });

    res.json({ success: true, message: "Message sent successfully!" });
  } catch (err) {
    console.error("❌ Contact Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Login =====
app.post("/api/secret-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false, message: "All fields required" });

    const user = await User.findOne({ username });
    if (!user) return res.status(401).json({ success: false, message: "User not found" });

    if (password !== user.password)
      return res.status(401).json({ success: false, message: "Incorrect password" });

    const message = user.sole ? "Hello my sole, this is for you" : "Login successful";
    res.json({ success: true, message, isAdmin: user.isAdmin, sole: user.sole });
  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Auto-create Default Users =====
const createDefaultUsers = async () => {
  try {
    const adminUser = process.env.DEFAULT_ADMIN_USER;
    const adminPass = process.env.DEFAULT_ADMIN_PASS;
    const privateUser = process.env.PRIVATE_USER;
    const privatePass = process.env.PRIVATE_PASSWORD;

    if (!adminUser || !adminPass || !privateUser || !privatePass) {
      console.error("❌ Missing environment variables for default users");
      return;
    }

    // Admin User
    const existingAdmin = await User.findOne({ username: adminUser });
    if (!existingAdmin) {
      await new User({
        username: adminUser,
        password: adminPass,
        isAdmin: true,
      }).save();
      console.log(`🚀 Admin created: ${adminUser}`);
    } else {
      console.log("✅ Admin already exists");
    }

    // Private User
    const existingPrivateUser = await User.findOne({ username: privateUser });
    if (!existingPrivateUser) {
      await new User({
        username: privateUser,
        password: privatePass,
        folderAccess: "private",
        sole: true,
        isAdmin: false,
      }).save();
      console.log(`🔒 Private user created: ${privateUser}`);
    } else {
      console.log("✅ Private user already exists");
    }
  } catch (err) {
    console.error("❌ Failed to create default users:", err);
  }
};

// ===== Admin: Create User =====
app.post("/api/admin/create-user", async (req, res) => {
  try {
    const { adminUsername, adminPassword, username, password, email, role, access } = req.body;
    if (!adminUsername || !adminPassword || !username || !password || !email)
      return res.status(400).json({ success: false, message: "All fields required" });

    const admin = await User.findOne({ username: adminUsername, isAdmin: true });
    if (!admin || admin.password !== adminPassword)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ success: false, message: "Username already exists" });

    const newUser = new User({
      username,
      password,
      isAdmin: role === "admin",
      folderAccess: access || "public",
    });
    await newUser.save();

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your Account Credentials",
      text: `Hello ${username},\nYour account has been created.\nUsername: ${username}\nPassword: ${password}\nRole: ${role || "User"}`,
    });

    res.json({ success: true, message: "User created successfully" });
  } catch (err) {
    console.error("❌ Create User Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Admin: List Users =====
app.get("/api/admin/users", async (req, res) => {
  try {
    const { adminUsername, adminPassword } = req.query;
    const admin = await User.findOne({ username: adminUsername, isAdmin: true });
    if (!admin || admin.password !== adminPassword)
      return res.status(403).json({ success: false, message: "Not authorized" });

    const users = await User.find({}, { password: 0 });
    res.json({ success: true, users });
  } catch (err) {
    console.error("❌ List Users Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Admin: Delete User =====
app.delete("/api/admin/delete-user", async (req, res) => {
  try {
    const { username } = req.body;
    const deleted = await User.findOneAndDelete({ username });
    if (!deleted)
      return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    console.error("❌ Delete User Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// ===== Google Drive: List Files =====
app.get("/api/list-files", async (req, res) => {
  try {
    const { type, username, password } = req.query;
    const user = await User.findOne({ username });
    if (!user || user.password !== password)
      return res.status(401).json({ success: false, message: "Unauthorized" });

    let folderId;
    if (user.sole) {
      folderId = PRIVATE_FOLDER_ID;
    } else if (type === "private") {
      if (!user.isAdmin)
        return res.status(403).json({ success: false, message: "Forbidden" });
      folderId = PRIVATE_FOLDER_ID;
    } else {
      folderId = PUBLIC_FOLDER_ID;
    }

    const response = await drive.files.list({
      q: `'${folderId}' in parents and (mimeType contains 'image/' or mimeType contains 'video/') and trashed=false`,
      fields: "files(id, name, mimeType)",
      orderBy: "createdTime desc",
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
    });

    const files = response.data.files.map((file) => ({
      id: file.id,
      name: file.name,
      mimeType: file.mimeType,
      url: `/api/files/${file.id}`,
    }));

    res.json({ success: true, files });
  } catch (err) {
    console.error("❌ Drive List Files Error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});

// ===== Google Drive: Stream Files =====
app.get("/api/files/:fileId", async (req, res) => {
  try {
    const { fileId } = req.params;
    const meta = await drive.files.get({
      fileId,
      fields: "mimeType, size",
      supportsAllDrives: true,
    });

    const mimeType = meta.data.mimeType;
    if (mimeType.startsWith("video/")) {
      const range = req.headers.range;
      if (!range) return res.status(400).send("Requires Range header for video streaming");

      const videoSize = Number(meta.data.size);
      const [startStr, endStr] = range.replace(/bytes=/, "").split("-");
      const start = Number(startStr);
      const end = endStr ? Number(endStr) : Math.min(start + 1e6, videoSize - 1);
      const contentLength = end - start + 1;

      res.writeHead(206, {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": mimeType,
      });

      const driveRes = await drive.files.get(
        { fileId, alt: "media", supportsAllDrives: true },
        { responseType: "stream" }
      );
      driveRes.data.pipe(res);
    } else {
      res.setHeader("Content-Type", mimeType);
      const driveRes = await drive.files.get(
        { fileId, alt: "media", supportsAllDrives: true },
        { responseType: "stream" }
      );
      driveRes.data.pipe(res);
    }
  } catch (err) {
    console.error("❌ Drive File Fetch Error:", err);
    res.status(500).send("Error fetching file");
  }
});

// ===== Start Server =====
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

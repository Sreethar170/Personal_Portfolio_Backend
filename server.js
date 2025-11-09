import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { google } from "googleapis";
import fs from "fs";
import multer from "multer";


dotenv.config();
const app = express();
const PORT = process.env.PORT || 8000;
app.use(express.urlencoded({ extended: true }));

const key = JSON.parse(fs.readFileSync('./service-account.json', 'utf-8'));


mongoose.connect(process.env.MONGODB_URI, { dbName: process.env.DB_NAME })
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error(" MongoDB Connection Error:", err));

app.use(cors());
app.use(express.json());


const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});


const PUBLIC_FOLDER_ID = process.env.PUBLIC_FOLDER_ID; 
const PRIVATE_FOLDER_ID = process.env.PRIVATE_FOLDER_ID; 

const auth = new google.auth.GoogleAuth({
  credentials: key,
  scopes: ["https://www.googleapis.com/auth/drive"],
});
const drive = google.drive({ version: "v3", auth });


const contactSchema = new mongoose.Schema({
  name: String,
  mail: String,
  message: String,
  createdAt: { type: Date, default: Date.now }
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


app.post("/contact", async (req, res) => {
  try {
    const { name, mail, message } = req.body;
    if (!name || !mail || !message) return res.status(400).json({ success: false, message: "All fields required" });

    const contact = new Contact({ name, mail, message });
    await contact.save();

    // Notify admin
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: `New Message from ${name}`,
      text: `Name: ${name}\nEmail: ${mail}\nMessage: ${message}`
    });

    // Acknowledge user
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: mail,
      subject: `Thanks for reaching out, ${name}!`,
      text: `Hi ${name},\nYour message has been received. We'll get back to you shortly.\n– Sreethar N J`
    });

    res.json({ success: true, message: "Message sent successfully!" });
  } catch (err) {
    console.error("Contact Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.post("/api/secret-login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ success: false, message: "All fields required" });

  try {
    const user = await User.findOne({ username });
    if (!user)
      return res.status(401).json({ success: false, message: "User not found" });
    if (password !== user.password)
      return res.status(401).json({ success: false, message: "Incorrect password" });

    const message = user.sole
      ? "Hello my sole this is for you"
      : "Login successful";

    res.json({
      success: true,
      message,
      isAdmin: user.isAdmin,
      sole: user.sole,
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
const createAdminUser = async () => {
  try {
    const existingAdmin = await User.findOne({ username: "admin" });
    if (existingAdmin) return console.log("✅ Admin already exists");

    const admin = new User({ username: "admin", password: "secret123", isAdmin: true });
    await admin.save();
    console.log("Admin created: username=admin, password=secret123");
  } catch (err) {
    console.error("Failed to create admin user:", err);
  }
};
createAdminUser();
app.post("/api/admin/create-user", async (req, res) => {
  const {
    adminUsername,
    adminPassword,
    username,
    password,
    email,
    role,
    access,
  } = req.body;
  if (!adminUsername || !adminPassword || !username || !password || !email)
    return res.status(400).json({ success: false, message: "All fields required" });
  try {
    const admin = await User.findOne({
      username: adminUsername,
      password: adminPassword,
      isAdmin: true,
    });
    if (!admin)
      return res.status(401).json({ success: false, message: "Unauthorized" });
    const existing = await User.findOne({ username });
    if (existing)
      return res.status(400).json({ success: false, message: "Username already exists" });
    const isAdminRole = role === "admin";
    const newUser = new User({
      username,
      password,
      isAdmin: isAdminRole,
      folderAccess: access || "public",
    });
    await newUser.save();
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your New Account Credentials",
      text: `Hello ${username},\nYour account has been created.\n\nUsername: ${username}\nPassword: ${password}\nAccess: ${access}\nRole: ${isAdminRole ? "Admin" : "User"}`,
    });
    res.json({ success: true, message: "New user created with role and folder access." });
  } catch (err) {
    console.error("Create User Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.get("/api/admin/users", async (req, res) => {
  try {
    const { adminUsername, adminPassword } = req.query;
    const admin = await User.findOne({ username: adminUsername, password: adminPassword, isAdmin: true });
    if (!admin) return res.status(403).json({ success: false, message: "Not authorized" });

    const users = await User.find({}, { password: 0 });
    res.json({ success: true, users });
  } catch (err) {
    console.error(" List Users Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.delete("/api/admin/delete-user", async (req, res) => {
  const { adminUsername, adminPassword, username } = req.body;
  try {
    const deleted = await User.findOneAndDelete({ username });
    if (!deleted)
      return res.status(404).json({ success: false, message: "User not found" });

    res.json({ success: true, message: "User deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error: " + err.message });
  }
});
app.get("/api/list-files", async (req, res) => {
  try {
    const { type, admin } = req.query; 
    const folderId = type === "private" ? PRIVATE_FOLDER_ID : PUBLIC_FOLDER_ID;
    if (type === "private" && admin !== "true") {
      return res.status(403).json({ success: false, message: "Unauthorized access to private files" });
    }
    const response = await drive.files.list({
      q: `'${folderId}' in parents and (mimeType contains 'image/' or mimeType contains 'video/') and trashed=false`,
      fields: "files(id, name, mimeType)",
      orderBy: "createdTime desc",
      includeItemsFromAllDrives: true,
      supportsAllDrives: true,
    });
    const files = response.data.files.map(file => ({
      id: file.id,
      name: file.name,
      mimeType: file.mimeType,
      url: `/api/files/${file.id}`,
    }));
    res.json({ success: true, files });
  } catch (err) {
    console.error("Drive List Files Error:", err);
    res.status(500).json({ success: false, message: err.message });
  }
});
app.get("/api/files/:fileId", async (req, res) => {
  try {
    const { fileId } = req.params;
    const meta = await drive.files.get({
      fileId,
      fields: "mimeType, size",
      supportsAllDrives: true,
    });
    const mimeType = meta.data.mimeType || "application/octet-stream";
    if (mimeType.startsWith("video/")) {
      const range = req.headers.range;
      if (!range) {
        return res.status(400).send("Requires Range header for video streaming");
      }
      const videoSize = parseInt(meta.data.size);
      const CHUNK_SIZE = 1 * 1024 * 1024;
      const start = Number(range.replace(/\D/g, ""));
      const end = Math.min(start + CHUNK_SIZE, videoSize - 1);
      const contentLength = end - start + 1;
      const headers = {
        "Content-Range": `bytes ${start}-${end}/${videoSize}`,
        "Accept-Ranges": "bytes",
        "Content-Length": contentLength,
        "Content-Type": mimeType,
      };
      res.writeHead(206, headers);
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
    console.error("Drive File Fetch Error:", err);
    res.status(500).send("Error fetching file");
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
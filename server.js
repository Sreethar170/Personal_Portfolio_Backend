// server.js
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import fetch from "node-fetch";

dotenv.config();
const app = express();
const PORT = process.env.PORT || 8000;

app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || "*", // set this on Render to your Vercel URL
}));
app.use(express.json());

/* MongoDB */
mongoose
  .connect(process.env.MONGODB_URI, { dbName: process.env.DB_NAME })
  .then(() => {
    console.log("✅ MongoDB Connected");
    createDefaultUsers();
  })
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

/* Mailer - use app password or transactional mail provider */
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

/* Models */
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

/* Helper: create default users */
const createDefaultUsers = async () => {
  try {
    const adminUser = process.env.DEFAULT_ADMIN_USER;
    const adminPass = process.env.DEFAULT_ADMIN_PASS;
    const privateUser = process.env.PRIVATE_USER;
    const privatePass = process.env.PRIVATE_PASSWORD;

    if (!adminUser || !adminPass || !privateUser || !privatePass) {
      console.warn("⚠️ Missing env vars for default users");
      return;
    }

    const existingAdmin = await User.findOne({ username: adminUser });
    if (!existingAdmin) {
      await new User({ username: adminUser, password: adminPass, isAdmin: true }).save();
      console.log(`🚀 Admin created: ${adminUser}`);
    } else console.log("✅ Admin exists");

    const existingPrivate = await User.findOne({ username: privateUser });
    if (!existingPrivate) {
      await new User({
        username: privateUser, password: privatePass, folderAccess: "private", sole: true, isAdmin: false
      }).save();
      console.log(`🔒 Private user created: ${privateUser}`);
    } else console.log("✅ Private user exists");
  } catch (err) {
    console.error("❌ Failed creating default users:", err);
  }
};

/* Contact endpoint */
app.post("/contact", async (req, res) => {
  try {
    const { name, mail, message } = req.body;
    if (!name || !mail || !message) return res.status(400).json({ success: false, message: "All fields required" });

    const contact = new Contact({ name, mail, message });
    await contact.save();

    // send notification to site owner
    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: process.env.EMAIL_USER,
        subject: `New Message from ${name}`,
        text: `Name: ${name}\nEmail: ${mail}\nMessage: ${message}`,
      });

      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: mail,
        subject: `Thanks for reaching out, ${name}!`,
        text: `Hi ${name},\n\nYour message has been received. We'll get back to you soon.\n\n– Team`,
      });
    } catch (mailErr) {
      console.warn("⚠️ Mail failed:", mailErr.message);
    }

    res.json({ success: true, message: "Message saved" });
  } catch (err) {
    console.error("❌ Contact Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* Secret login */
app.post("/api/secret-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ success: false });

    const user = await User.findOne({ username });
    if (!user || user.password !== password)
      return res.status(401).json({ success: false });

    let access = {
      publicUrl: null,
      privateUrl: null,
    };

    if (user.isAdmin) {
      access.publicUrl = process.env.PUBLIC_SCRIPT_URL;
      access.privateUrl = process.env.PRIVATE_SCRIPT_URL;
    } else if (user.sole) {
      access.privateUrl = process.env.PRIVATE_SCRIPT_URL;
    } else {
      access.publicUrl = process.env.PUBLIC_SCRIPT_URL;
    }

    res.json({
      success: true,
      username: user.username,
      isAdmin: user.isAdmin,
      sole: user.sole,
      access,
    });
  } catch (err) {
    res.status(500).json({ success: false });
  }
});

/* Admin: create user */
app.post("/api/admin/create-user", async (req, res) => {
  try {
    const { adminUsername, adminPassword, username, password, email, role, access } = req.body;
    if (!adminUsername || !adminPassword || !username || !password || !email) return res.status(400).json({ success: false, message: "All fields required" });

    const admin = await User.findOne({ username: adminUsername, isAdmin: true });
    if (!admin || admin.password !== adminPassword) return res.status(401).json({ success: false, message: "Unauthorized" });

    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ success: false, message: "Username exists" });

    const newUser = new User({ username, password, isAdmin: role === "admin", folderAccess: access || "public" });
    await newUser.save();

    try {
      await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your Account Credentials",
        text: `Hello ${username},\nYour account has been created.\nUsername: ${username}\nPassword: ${password}\nRole: ${role || "User"}`,
      });
    } catch (mailErr) {
      console.warn("⚠️ Could not email new user:", mailErr.message);
    }

    res.json({ success: true, message: "User created" });
  } catch (err) {
    console.error("❌ Create User Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* Admin: list users */
app.get("/api/admin/users", async (req, res) => {
  try {
    const { adminUsername, adminPassword } = req.query;
    const admin = await User.findOne({ username: adminUsername, isAdmin: true });
    if (!admin || admin.password !== adminPassword) return res.status(403).json({ success: false, message: "Not authorized" });

    const users = await User.find({}, { password: 0 });
    res.json({ success: true, users });
  } catch (err) {
    console.error("❌ List Users Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

app.delete("/api/admin/delete-user", async (req, res) => {
  try {
    const { username } = req.body;
    const deleted = await User.findOneAndDelete({ username });
    if (!deleted) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, message: "User deleted" });
  } catch (err) {
    console.error("❌ Delete User Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

/* === Google Drive public folder listing & file serving ===
   NOTE: Files MUST be shared as "Anyone with the link -> Viewer" in Drive.
   This implementation uses a free Google API KEY and public folder listing.
*/
const GOOGLE_API_KEY = process.env.GOOGLE_API_KEY;
const PUBLIC_FOLDER_ID = process.env.PUBLIC_FOLDER_ID;
const PRIVATE_FOLDER_ID = process.env.PRIVATE_FOLDER_ID || null;
const PUBLIC_SCRIPT_URL = process.env.PUBLIC_SCRIPT_URL;
const PRIVATE_SCRIPT_URL = process.env.PRIVATE_SCRIPT_URL ;
/* LIST FILES (GOOGLE SCRIPT) */
app.get("/api/list-files", async (req, res) => {
  try {
    const { scriptUrl } = req.query;
    if (!scriptUrl) return res.status(400).json({ success: false });

    const response = await fetch(scriptUrl);
    const files = await response.json();

    res.json({ success: true, files });
  } catch {
    res.status(500).json({ success: false });
  }
});

/* STREAM FILE */
app.get("/api/files", async (req, res) => {
  const { url } = req.query;
  if (!url) return res.status(400).send("Missing file url");

  const r = await fetch(url);
  res.setHeader("Content-Type", r.headers.get("content-type"));
  r.body.pipe(res);
})
/* Health */
app.get("/", (req, res) => res.send("OK"));

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

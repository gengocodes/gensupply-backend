import express from "express";
import mysql from "mysql";
import cors from "cors";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import "dotenv/config";

const PORT = process.env.PORT || 10000;
const FRONT = process.env.FNT_HOST || "http://localhost:3000";
const crypt = 5;

const app = express();
app.use(express.json());

app.use(
  cors({
    origin: FRONT,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER,
  password: process.env.DB_PW,
  database: process.env.DB_NAME,
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ Error: "You are not authenticated!" });
  }
  jwt.verify(token, process.env.JWT_TOKEN, (err, decoded) => {
    if (err) {
      return res.json({ Error: "Session timed out!" });
    }
    req.user = decoded;
    next();
  });
};

app.post("/register", (req, res) => {
  const checkSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkSql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Database error checking email." });
    if (data.length > 0) return res.json({ Error: "Email already in use." });

    const sql = "INSERT INTO users (`name`, `email`, `password`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), crypt, (err, hash) => {
      if (err) return res.json({ Error: "Error hashing password." });
      const values = [req.body.name, req.body.email, hash];
      db.query(sql, [values], (err, result) => {
        if (err)
          return res.json({ Error: "Error inserting data to the server." });
        return res.json({ Status: "Registration Success!" });
      });
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Database not initialized!" });
    if (data.length === 0) return res.json({ Error: "Unregistered Email!" });

    bcrypt.compare(
      req.body.password.toString(),
      data[0].password,
      (err, response) => {
        if (err) return res.json({ Error: "Error comparing passwords." });
        if (!response) return res.json({ Error: "Wrong Password!" });

        const user = {
          id: data[0].id,
          name: data[0].name,
          email: data[0].email,
        };

        const token = jwt.sign(user, process.env.JWT_TOKEN, {
          expiresIn: "10m",
        });
        res.cookie("token", token, {
          httpOnly: true,
          secure: true,
          sameSite: "None",
        });

        return res.json({ Status: "User Authenticated!" });
      }
    );
  });
});

app.post("/updatename", verifyUser, (req, res) => {
  const username = req.body.username;
  const email = req.user.email;

  const sql = "UPDATE users SET name = ? WHERE email = ?";
  db.query(sql, [username, email], (err, result) => {
    if (err) return res.json({ Error: "Failed to update username" });

    const newUser = {
      id: req.user.id,
      name: username,
      email: req.user.email,
    };

    const newToken = jwt.sign(newUser, process.env.JWT_TOKEN, {
      expiresIn: "10m",
    });

    res.cookie("token", newToken, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
    });

    return res.json({ Status: "Username Updated!" });
  });
});

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "User Authenticated!", user: req.user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: "Logged out!" });
});

app.get("/supply", verifyUser, (req, res) => {
  const userId = req.user.id;
  const sql = "SELECT * FROM supplies WHERE user_id = ?";
  db.query(sql, [userId], (err, result) => {
    if (err) return res.json({ Error: "Failed to fetch supplies" });
    return res.json(result);
  });
});

app.post("/supply/create", verifyUser, (req, res) => {
  const { name, count } = req.body;
  const userId = req.user.id;
  const sql = "INSERT INTO supplies (user_id, name, count) VALUES (?, ?, ?)";
  db.query(sql, [userId, name, count], (err, result) => {
    if (err) return res.json({ Error: "Failed to create supply" });
    return res.json({ Status: "Supply Created!" });
  });
});

app.delete("/supply/delete/:id", verifyUser, (req, res) => {
  const userId = req.user.id;
  const supplyId = req.params.id;
  const sql = "DELETE FROM supplies WHERE id = ? AND user_id = ?";
  db.query(sql, [supplyId, userId], (err, result) => {
    if (err) return res.json({ Error: "Failed to delete supply" });
    return res.json({ Status: "Supply Deleted!" });
  });
});

app.put("/supply/update/:id", verifyUser, (req, res) => {
  const { name, count } = req.body;
  const userId = req.user.id;
  const supplyId = req.params.id;
  const sql =
    "UPDATE supplies SET name = ?, count = ? WHERE id = ? AND user_id = ?";
  db.query(sql, [name, count, supplyId, userId], (err, result) => {
    if (err) return res.json({ Error: "Failed to update supply" });
    return res.json({ Status: "Supply Updated!" });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

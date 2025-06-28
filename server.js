import express from "express"; //server side
import mysql from "mysql"; //database
import cors from "cors"; //access backend api using frontend
import cookieParser from "cookie-parser"; //cookies
import jwt from "jsonwebtoken"; //authentication(security)
import bcrypt from "bcrypt"; //hash pwds
import session from "express-session";
const PORT = process.env.BCK_HOST || 1234;
const FRONT = process.env.FNT_HOST || "http://localhost:3000";
import "dotenv/config";

const app = express();
app.use(express.json());
app.use(
  session({
    secret: process.env.EXPRESS_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);
app.use(
  cors({
    origin: FRONT,
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);
app.use(cookieParser());
const crypt = 5;

const db = mysql.createConnection({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER,
  password: process.env.DB_PW,
  database: process.env.DB_NAME,
});

app.post("/register", (req, res) => {
  const checkSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkSql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Database error checking email." });
    if (data.length > 0) {
      return res.json({ Error: "Email already in use." });
    }

    const sql = "INSERT INTO users (`name`, `email`, `password`) VALUES (?)";
    bcrypt.hash(req.body.password.toString(), crypt, (err, hash) => {
      if (err) return res.json({ Error: "Error hashing password." });
      console.log("Registered!");
      const values = [req.body.name, req.body.email, hash];
      db.query(sql, [values], (err, result) => {
        if (err) {
          return res.json({ Error: "Error inserting data to the server." });
        }
        return res.json({ Status: "Registration Success!" });
      });
    });
  });
});

app.post("/updatename", (req, res) => {
  const username = req.body.username;
  const email = req.session.user?.email;

  if (!email) {
    return res.json({ Error: "Unauthorized or session expired" });
  }

  const sql = "UPDATE users SET name = ? WHERE email = ?";
  db.query(sql, [username, email], (err, result) => {
    if (err) {
      console.error("Error updating name:", err);
      return res.json({ Error: "Failed to update username" });
    }
    const newUser = {
      id: req.session.user.id,
      name: username,
      email: req.session.user.email,
    };
    req.session.user = newUser;

    const newToken = jwt.sign(newUser, process.env.JWT_TOKEN, {
      expiresIn: "10m",
    });
    res.cookie("token", newToken);
    const tokenExpiry = new Date(Date.now() + 10 * 60 * 1000);
    console.log(
      `🔐 Token refreshed for ${
        newUser.name
      } will expire at: ${tokenExpiry.toLocaleString()}`
    );
    return res.json({ Status: "Username Updated!" });
  });
});
app.post("/login", (req, res) => {
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) return res.json({ Error: "Database not initialized!" });
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err)
            return res.json({
              Error:
                "Password does not match! Error in comparing the password.",
            });
          if (response) {
            const user = {
              id: data[0].id,
              name: data[0].name,
              email: data[0].email,
            };
            req.session.user = user;
            const token = jwt.sign(user, process.env.JWT_TOKEN, {
              expiresIn: "10m",
            });
            res.cookie("token", token);
            return res.json({ Status: "User Authenticated!" });
          } else {
            return res.json({ Error: "Wrong Password!" });
          }
        }
      );
    } else {
      return res.json({ Error: "Unregistered Email!" });
    }
  });
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({
      Error: "You are not authenticated!",
    });
  } else {
    jwt.verify(token, process.env.JWT_TOKEN, (err, decoded) => {
      if (err) {
        return res.json({
          Error: "Session timed out!",
        });
      } else {
        req.user = decoded;
        next();
      }
    });
  }
};

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

app.get("/", verifyUser, (req, res) => {
  return res.json({ Status: "User Authenticated!", user: req.user });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ Status: "Logged out!" });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

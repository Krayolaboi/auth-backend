const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

const SECRET = "mysecretkey";

const db = new sqlite3.Database("./users.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    hwid TEXT
)
`);

app.post("/register", async (req, res) => {
    const { username, password } = req.body;

    const hash = await bcrypt.hash(password, 10);

    db.run(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hash],
        (err) => {
            if (err) {
                return res.json({
                    success: false,
                    message: "User already exists"
                });
            }

            res.json({
                success: true
            });
        }
    );
});

app.post("/login", (req, res) => {
    const { username, password, hwid } = req.body;

    db.get(
        "SELECT * FROM users WHERE username = ?",
        [username],
        async (err, user) => {

            if (!user) {
                return res.json({
                    success: false,
                    message: "Invalid account"
                });
            }

            const valid = await bcrypt.compare(password, user.password);

            if (!valid) {
                return res.json({
                    success: false,
                    message: "Wrong password"
                });
            }

            if (!user.hwid) {
                db.run(
                    "UPDATE users SET hwid = ? WHERE id = ?",
                    [hwid, user.id]
                );
            }
            else if (user.hwid !== hwid) {
                return res.json({
                    success: false,
                    message: "HWID mismatch"
                });
            }

            const token = jwt.sign(
                { id: user.id },
                SECRET,
                { expiresIn: "7d" }
            );

            res.json({
                success: true,
                token
            });
        }
    );
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
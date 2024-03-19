import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "secrets",
    password: "shubshresdev",
    port: 5432,
});
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
    res.render("home.ejs");
});

app.get("/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/register", (req, res) => {
    res.render("register.ejs");
});

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    // console.log("Username: ", username);
    // console.log("Password: ", password);

    try {
        const checkResult = await db.query(
            "SELECT * FROM users WHERE email =$1",
            [email]
        );

        if (checkResult.rows.length > 0) {
            res.send("Email already exists.");
        } else {
            // add user to db
            // hash password
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log("Error hashing password: ", err);
                } else {
                    const result = await db.query(
                        "INSERT INTO users (email, password) VALUES ($1, $2)",
                        [email, hash]
                    );
                    console.log(result);
                    res.render("secrets.ejs");
                }
            });
        }
    } catch (err) {
        console.log(err);
    }
});

app.post("/login", async (req, res) => {
    const email = req.body.username;
    const loginPassword = req.body.password;

    // console.log("Username: ", username);
    // console.log("Password: ", password);

    try {
        const userDetails = await db.query(
            "SELECT * FROM users WHERE email =$1",
            [email]
        );

        if (userDetails.rows.length > 0) {
            const storedUser = userDetails.rows[0];
            const storedHashedPassword = storedUser.password;

            // if (password === storedPassword) {
            bcrypt.compare(
                loginPassword,
                storedHashedPassword,
                (err, result) => {
                    if (err) {
                        console.log("Error comparing passwords:", err);
                    } else {
                        if (result) {
                            res.render("secrets.ejs");
                        } else {
                            res.send("Incorrect Password");
                        }
                    }
                }
            );
        } else {
            res.send("User not found");
        }
    } catch (err) {
        console.log(err);
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

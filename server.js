const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const jwt = require("jsonwebtoken");

dotenv.config();

const uri = process.env.MONGO_URI;
const saltRounds = process.env.SALT_ROUNDS;

const app = express();
app.use(bodyParser.json());

//Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const hashedPassword = await bcrypt.hash(password, parseInt(saltRounds));

    const user = await collection.insertOne({
      username: username,
      password: hashedPassword,
    });
    res.json({
      success: true,
      message: "Register successful",
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Register failed",
    });
  } finally {
    await client.close();
  }
});

//Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const user = await collection.findOne({ username: username });

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        const token = jwt.sign({ username: username }, process.env.SECRET, {
          expiresIn: "1h",
        });
        res.json({
          success: true,
          message: "login successful",
          token: token,
        });
      } else {
        res.json({
          success: false,
          message: "login failed password wrong",
        });
      }
    } else {
      res.json({
        success: false,
        message: "login failed else",
      });
    }
  } catch (error) {
    res.json({
      success: false,
      message: "login failed catch error",
    });
  } finally {
    await client.close();
  }
});

//Verify Token
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (typeof token !== "undefined") {
    jwt.verify(token, process.env.SECRET, (err, authData) => {
      if (err) {
        res.sendStatus(403);
      } else {
        next();
      }
    });
  } else {
    res.sendStatus(403);
  }
}
//Get All users
app.get("/users", verifyToken, async (req, res) => {
  const client = new MongoClient(uri);
  try {
    await client.connect();
    const database = client.db("users");
    const collection = database.collection("users");

    const users = await collection.find({}).toArray();

    res.json({
      success: true,
      message: "Get users successful",
      data: users,
    });
  } catch (error) {
    res.json({
      success: false,
      message: "Get users failed : ", 
    });
  } finally {
    await client.close();
  }
});

//-----------------------------------------------------------------------------------------------
//Login Mockup Data

// app.post("/login", (req, res) => {
//   const username = req.body.username;
//   const password = req.body.password;

//   const mockUsername = "admin";
//   const mockPassword = "admin";

//   if (username === mockUsername && password === mockPassword) {
//     res.json({
//       success: true,
//       message: "Login successed",
//     });
//   } else {
//     res.json({
//       success: false,
//       message: "login failes",
//     });
//   }
// });
//-----------------------------------------------------------------------------------------------

app.get("/", (req, res) => {
  res.send("Hello World");
});

app.listen(3000, () => {
  console.log("Server is running on port http://localhost:3000");
});

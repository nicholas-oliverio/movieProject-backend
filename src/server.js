import express from "express";
import cors from "cors";
import { createRequire } from "node:module";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const require = createRequire(import.meta.url);
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const app = express();
app.use(express.json());
app.use(
  cors({
    origin: "http://localhost:8080",
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"], // FIX: consenti Authorization
  })
);

const config = {
  PORT: process.env.PORT || 3000,
  TOKEN_SIGN_KEY: process.env.TOKEN_SIGN_KEY,
  MONGODB_URI: process.env.MONGODB_URI,
  MONGODB_DB: process.env.MONGODB_DB,
};

const client = new MongoClient(config.MONGODB_URI, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

let db;

async function initDb() {
  await client.connect();
  await client.db("admin").command({ ping: 1 });
  db = client.db(config.MONGODB_DB);
  console.log("MongoDB connesso");
}
initDb().catch((e) => {
  console.error("Errore connessione Mongo:", e);
  process.exit(1);
});

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token" });
  const [scheme, token] = auth.split(" ");
  if (!/^Bearer$/i.test(scheme) || !token) {
    return res.status(401).json({ error: "Invalid auth header" });
  }
  try {
    const payload = jwt.verify(token, config.TOKEN_SIGN_KEY);
    req.user = payload;
    next();
  } catch (err) {
    console.error("[JWT verify error]", err.name, err.message);
    return res.status(401).json({ error: "Invalid token" });
  }
}

app.post("/login", async (req, res) => {
  try {
    const { name, password } = req.body;
    const user = await db.collection("users").findOne({ name });
    if (!user) return res.status(404).json({ rc: 1, msg: `User ${name} not found` });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ rc: 1, msg: "Invalid credentials" });
    const payload = { sub: user._id.toString(), name: user.name };
    const token = jwt.sign(payload, config.TOKEN_SIGN_KEY, { expiresIn: "1h" });
    return res.status(200).json({ rc: 0, msg: "Login successful", token });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ rc: 1, msg: err.toString() });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) {
      return res.status(400).json({ rc: 1, msg: "username, email e password sono obbligatori" });
    }
    const exists = await db.collection("users").findOne({ $or: [{ name }, { email }] });
    if (exists) return res.status(409).json({ rc: 1, msg: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 12);
    await db.collection("users").insertOne({ name, email, password: hashedPassword });
    return res.status(201).json({ rc: 0, msg: "Register successful" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ rc: 1, msg: err.toString() });
  }
});

app.use(authMiddleware);

app.get("/me", async (req, res) => {
  try {
    const userId = req.user.sub;
    const user = await db.collection("users").findOne({ _id: new ObjectId(userId) }, { projection: { name: 1, email: 1 } });
    if (!user) return res.status(404).json({ error: "User not found" });
    return res.json({ id: userId, name: user.name, email: user.email });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/users/:id", async (req, res) => {
  try {
    const id = String(req.params.id);
    const _id = new ObjectId(id);
    const user = await db.collection("users").findOne(_id, { projection: { name: 1, email: 1 } });
    if (!user) return res.status(404).json({ rc: 1, msg: "User not found" });
    return res.status(200).json({ rc: 0, msg: "User found successful", data: user });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ rc: 1, msg: "Invalid ID" });
  }
});

app.get("/movieList", async (req, res) => {
  try {
    const movies = await db.collection("movies").find({}, { projection: { title: 1, genres: 1, year: 1 } }).toArray();
    return res.status(200).json({ rc: 0, msg: "Movie list download successful", data: movies });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ rc: 1, msg: err.toString() });
  }
});

app.get("/movieList/:id", async (req, res) => {
  try {
    const _id = new ObjectId(String(req.params.id));
    const movie = await db.collection("movies").findOne({ _id },{projection: { title: 1, year: 1, poster: 1, lastupdated: 1,fullplot:1 },});
    if (!movie) return res.status(404).json({ rc: 1, msg: "Movie not found!" });
    return res.json({ rc: 0, msg: "Movie successful found", data: movie });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ rc: 1, msg: "Invalid ID" });
  }
});

app.delete("/movieList/:id", async (req, res) => {
  try{
    const _id = new ObjectId(String(req.params.id));
    const movie = await db.collection("movies").findOneAndDelete({_id})
    if(!movie) return res.status(404).json({rc:1 , msg: "Movie not found!"})
      return res.json({ rc: 0, msg: "Movie successful delete!", data: movie });
  }catch(err){
    console.error(err)
    return res.status(500).json({ rc:1 , msg: "Impossible to delete movie"})
  }
})

app.listen(config.PORT, () => {
  console.log(`Server in ascolto su http://localhost:${config.PORT}`);
});

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
    allowedHeaders: ["Content-Type", "Authorization"],
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

app.get("/movies", async (req, res) => {
  try {
    const { id, name, year, genres } = req.query;
    const query = {};

    if (id) {
    if (!ObjectId.isValid(id)) {
        return res.status(400).json({ rc: 1, msg: "Invalid id format" });
      }
      const projection = { projection: { _id: 1, title: 1, genres: 1, year: 1,fullplot:1,poster:1 } };
      const item = await db
        .collection("movies")
        .findOne({ _id: new ObjectId(id) }, projection);

      if (!item) {
        return res.status(404).json({ rc: 1, msg: "Movie not found" });
      }

      return res
        .status(200)
        .json({ rc: 0, msg: "Movie fetched successfully", data: item });
    }
    else{
    if (name && name.trim()) {
      query.title = { $regex: `^${name.trim()}`, $options: "i" };
    }
    if (year) {
      const y = parseInt(year, 10);
      if (!Number.isNaN(y)) query.year = y;
    }
    if (genres) {
      const list = Array.isArray(genres)
        ? genres
        : String(genres).split(",").map(g => g.trim()).filter(Boolean);
      if (list.length) query.genres = { $in: list };
    }

    const projection = { projection: { _id: 1, title: 1, genres: 1, year: 1 } };
    const items = await db.collection("movies").find(query, projection).toArray();

    return res.status(200).json({
      rc: 0,
      msg: "Movies fetched successfully",
      data: items
    });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ rc: 1, msg: err.toString() });
  }
});

app.delete("/movies/:id", async (req, res) => {
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

app.post("/movies", async (req,res) =>{
    try{
      const { title, year, poster, fullplot } = req.body || {};
      if (!title || !year || !fullplot) {
        return res.status(400).json({ rc: 1, msg: "title, year e fullplot !" });
      }
      const exists = await db.collection("movies").findOne({ $or: [{ title }, { fullplot }] });
      if (exists) return res.status(409).json({ rc: 1, msg: "Movie already exists" });
      const movie = await db.collection("movies").insertOne({ title, year, poster, tomatoes:{lastupdated: new Date()},fullplot});
      return res.status(201).json({ rc: 0, msg: "Movie add successful", data: movie });
    }
    catch(err){
      console.error(err)
      return res.status(500).json({ rc:1 , msg: "Impossible to add movie"})
    }
})

app.patch("/movies/:id", async (req, res) => {
  try {
    const _id = new ObjectId(String(req.params.id));
    const allowedFields = ["title", "year", "poster", "fullplot"];
    const set = {};

    for (const key of allowedFields) {
      if (req.body[key] !== undefined) {
        set[key] = req.body[key];
      }
    }

    if (Object.keys(set).length === 0) {
      return res.status(400).json({ rc: 1, msg: "Nessun campo valido da aggiornare" });
    }

    await db.collection("movies").updateOne({ _id }, { $set: set });
    const doc = await db.collection("movies").findOne({ _id });
    if (!doc) {
      return res.status(404).json({ rc: 1, msg: "Movie not found" });
    }

    return res.status(200).json({ rc: 0, data: doc });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ rc: 1, msg: err.message });
  }
});
app.patch("/pokemon/:teamId" , async (req,res) =>{
  try{
  const { teamId } = req.params   
  const newMember = req.body
  
  const result = await db.collection("teams").updateOne({ _id: teamId, $expr: { $lt: [ { $size: "$members" }, 6 ] } }, { $push: { members: newMember } })
   if (result.modifiedCount === 0) {
      return res.status(400).json({ error: "Team pieno (max 6) o non trovato" })
    } 
  return res.status(200).json({rc:0 ,msg: 'successfull add', data: result})
  } catch (err) {
    console.error(err)
    return res.status(500).json({ error: "Errore server" })
  }
})

app.patch("/pokemon/:teamId/removeByName" , async (req,res) => {
  try{
  const {teamId} = req.params
  const {name} = req.body

   if (!name || typeof name !== "string") {
      return res.status(400).json({ error: "Serve un 'name' valido nel body" });
    }

   const result = await db.collection("teams").updateOne(
  { _id: teamId },               
  { $pull: { members: { name: name } } } 
  )

  if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Team non trovato" });
    }
    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: "Pokémon non trovato nella squadra" });
    }

  return res.status(200).json({rc:0 ,msg: 'successfull delete'})
}catch(err){
  console.error(err)
  return res.status(500).json({ error: "Errore server" })
}
})
app.get("/pokemon/:teamId", async (req, res) => {
  try {
    const { teamId } = req.params;

    const team = await db.collection("teams").findOne(
      { _id: teamId },
      { projection: { _id:1, name: 1, members: 1 } }
    );

    if (!team) {
      return res.status(404).json({ error: "Team not found" });
    }

    const members = [...(team.members ?? []), null, null, null, null, null].slice(0, 6);

    return res.status(200).json({
      rc: 0,
      msg: "Team fetched successfully",
      data: { ...team, members }
    });
  } catch (err) {
    console.error("Errore GET /pokemon/:teamId:", err);
    return res.status(500).json({ error: "Errore server" });
  }
});



app.listen(config.PORT, () => {
  console.log(`Server in ascolto su http://localhost:${config.PORT}`);
});

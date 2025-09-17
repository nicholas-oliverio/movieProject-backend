import express from "express";
import cors from "cors";
import { createRequire } from 'node:module'
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import dotenv from "dotenv"

const require = createRequire(import.meta.url)
const app = express();
app.use(express.json());
dotenv.config();
app.use(cors({
  origin: 'http://localhost:8080', 
  credentials: true                 
}));
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const config = {
  PORT: process.env.PORT || 3000,
  TOKEN_SIGN_KEY: process.env.TOKEN_SIGN_KEY,
  MONGODB_URI: process.env.MONGODB_URI,
  MONGODB_DB: process.env.MONGODB_DB
}
const client = new MongoClient(config.MONGODB_URI, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});


app.use((req, res, next) => {
  // Rotte pubbliche
  if (req.path === "/login" || req.path === "/register") {
    return next();
  }

  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    // nessun token → redirect a /login
    return res.redirect("/login");
  }

  const token = authHeader.split(" ")[1]; // "Bearer <token>"
  if (!token) {
    return res.redirect("/login");
  }

  try {
    const payload = jwt.verify(token, config.TOKEN_SIGN_KEY);
    req.user = payload; // payload disponibile nelle rotte successive
    return next();
  } catch (err) {
    console.error("Token error:", err.message);
    return res.redirect("/login");
  }
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    await client.close();
  }
}run().catch(console.dir);

app.post("/login", async (req,res) =>{
  const {name,password} = req.body;
  try{
    await client.connect()
    const db = client.db(config.MONGODB_DB)
    const user = await db.collection('users').findOne({name})
    if (!user) return res.status(404).json({ rc: 0, msg:`User ${name} not found`})
    const match = await bcrypt.compare(password, user.password)
    if(!match) return res.status(404).json({ rc:1, msg:`Invalid credentials`})
    const payload = { sub: user._id.toString(), name: user.name };
    const token = jwt.sign(payload, config.TOKEN_SIGN_KEY, {expiresIn: '1h'})
    res.status(200).json({ rc:1 , msg: 'Login successful', token: token })
  }catch(err){
    console.error(err);
    res.status(400).json({ rc:1, msg: err.toString() })
  }finally{
    await client.close();
  }
})

app.put("/register", async (req,res) => {
  try{
  await client.connect()
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) {
      return res.status(400).json({ rc: 1, msg: "username, email e password sono obbligatori" });
  } 
  const hashedPassword = await bcrypt.hash(password,12);

  const newUser = {
    name,
    email,
    password: hashedPassword,
  } 
  const db = client.db(config.MONGODB_DB)
  const data = await db.collection('users').insertOne(newUser)
  console.log('New user added',data)
  res.status(201).send({ rc: 0,msg:'Register succesful'})
  }catch(err){
    console.error(err)
    res.status(400).json({ rc: 1, msg: err.toString() })
  }finally{
    await client.close()
  }
})

app.get("/movieList", async (req,res) => {
  try{
  await client.connect()
  const movies = await client
  .db(config.MONGODB_DB)
  .collection('movies')
  .find( {}, {projection : {
    title: 1, 
    year: 1,
    cast: 1,
    poster: 1,}}).toArray()
  return res.status(200).json({rc:0, msg: 'Movie list download succesful',data: movies})
  }catch(err){
    console.error(err)
    return res.status(500).json({ rc:1 , msg: err.toString() })
  }finally{
    await client.close()
  }
})

app.get("/movieList/:id" , async (req,res) =>{
  try{
    await client.connect()
    const db = client.db(config.MONGODB_DB)
    const id = String(req.params.id)
    const _id = new ObjectId(id)

    const movie = await db.collection('movies').findOne(
      {_id},
      {projection: { title: 1, year: 1, poster: 1,lastupdated: 1}}
    )
    if(!movie){
      return res.status(404).json({rc: 1 , msg: 'Movie not found' })
    }
    console.log(movie)
    return res.json({rc:0 , msg: 'Movie succesful found' , data: movie })
  }catch(err){
    console.error(err)
    return res.status(500).json({rc: 1 , msg: 'Invalid ID'})
  }
}) 

app.get("/users/:id" , async (req,res) =>{
   try{
    await client.connect()
    const db = client.db(config.MONGODB_DB)
    const id = String(req.params.id)
    const _id = new ObjectId(id)

    const user = await db.collection('users').findOne(
      {_id},
      {projection: {name: 1, email:1}}
    )
    if(!user){
      return res.status(404).json({rc:1, msg: 'User not found'})
    }
    return res.status(200).json({rc:0 , msg: 'User found succesful', data: user})
   }catch(err){
    console.error(err)
    return res.status(500).json({rc:1,msg: 'User error'})
   } 
})

app.listen(config.PORT, () => {
  console.log(`Server in ascolto su http://localhost:${config.PORT}`);
});

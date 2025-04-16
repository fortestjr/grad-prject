
// import mongoose from "mongoose"
// import errorHandler from "../middlewares/errorHnadler.js"

import express from "express";
import {fileURLToPath} from "url"
import errorHandler from "./middleware/errorHandler.js"
import ipscanningRouter from "./routes/ipscanning.js"
import * as path from "path";
import dbConnection from "./db/db.js"
const PORT = process.env.PORT || 3000
const app = express()

app.use(express.json());

// const __filename = fileURLToPath(import.meta.url)
// const __dirname = path.dirname(__filename)
// console.log("Dir Name:" , __dirname , "fileName:" , __filename)

// console.log(typeof path.dirname);  // Should log "function"


(async () => {
    const db = await dbConnection()    
})()

app.use("/healthz" , (req , res)=>{res.send({status : "ok"})})
app.use("/ipscan" , ipscanningRouter)
// app.use("/signup" , signUp)
app.use(errorHandler);

app.listen(PORT, () => {
    console.log(`Server Listen To ${PORT}`)
});
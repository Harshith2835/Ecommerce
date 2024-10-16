import path from 'path'
import express from 'express'
import dotenv from 'dotenv'
import cookieParser from 'cookie-parser'
import connectdb from './config/dbconfig.js'
import UserRoutes from './routes/userroutes.js'

dotenv.config();
const port=process.env.PORT
connectdb();
const app=express()
app.use(express.json())
app.use(express.urlencoded({extended:true}))
app.use(cookieParser())

app.get("/",(req,res)=>{
    res.send("helloworld")
})

app.use("/api/users",UserRoutes)

app.listen(port,()=>console.log(`Server is running on port ${port}`))
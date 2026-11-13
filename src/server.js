import express from "express"
import jwt from "jsonwebtoken"
import { prisma } from "./lib/prisma.ts"
import cookieParser from "cookie-parser"
import bcrypt from "bcryptjs"
import cors from "cors"


const JWT_SECRET = `${process.env.JWT_SECRET}`
const PORT = `${process.env.PORT}`
const app = express()
app.use(cors())
app.use(cookieParser())
app.use(express.json())


function autenticar(req, res, next){
    const token = req.cookies.token

    if(!token){
        return res.status(401).json("Acesso negado")
    }

    try{
        const usuario = jwt.verify(token, JWT_SECRET)
        req.usuario = usuario
        next()
    } catch(error) {
        return res.status(403).json("Token inválido ou expirado.")
    }
}

app.get("/users", async (req, res) => {
    const usuarios = await prisma.user.findMany()
    res.json(usuarios)
})

app.post("/login", async (req, res) => {
    const { email, senha } = req.body

    try {
        const user = await prisma.user.findUnique({
            where: { email }
        })
        const token = jwt.sign(
            { id: user.id, email: user.email },
            JWT_SECRET,
            { expiresIn: "2h" }
        )

        res.cookie("token", token, {
            httpOnly: true,
            secure: false,
            sameSite: "lax",
            maxAge: 3600000
        })

        return res.status(200).json({ message: "Login realizado com sucesso" })

    } catch (error) {
        return res.status(500).json({ message: "Erro interno" })
    }
})


app.listen(PORT, () => {
    console.log("rodando.")
})
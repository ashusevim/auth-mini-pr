import express, { type Request, type Response } from "express"
import dotenv from "dotenv"
import cookieParser from "cookie-parser"
import bcypt from "bcrypt"
import { users, type User } from "./users.js"
dotenv.config()

const app = express()
const port = process.env.PORT || 3000

app.use(express.json());
app.use(cookieParser());

app.post('/signup', async (req: Request, res: Response) => {
    try {
        const { name, email, password } = req.body

        if (!name || !email || !password) {
            return res.status(400).json({ message: "All the fields are required" })
        }

        const existingUser = users.find((user) => { user.email == email })

        if (existingUser) {
            return res.status(400).json({ message: "User already exists" })
        }

        // saltrounds shows how many times the hash is internally processed
        const saltRound = 10;
        const hashedPassword = await bcypt.hash(password, saltRound)

        const newUser: User = {
            id: users.length + 1,
            name,
            email,
            hashedPassword,
        }

        users.push(newUser)
        return res.status(201).json({ message: "User registered successfully", userId: newUser.id })
    } catch (error) {
        return res.status(500).json({ message: "Error while registering user!!" })
    }
})

app.get('/users', (req: Request, res: Response) => {
    return res.status(200).json({ users })
})

app.get('/users/:id', (req: Request, res: Response) => {
    try {
        const { id } = req.body;
        if(!id){
            return res.status(400).json({ message: "All the fields are required" })
        }

        const user = users.find((user) => user.id == id)
        return res.status(200).json({ user })
    } catch (error) {
        
    }
})

app.get('/', (req: Request, res: Response) => {
    res.send('Auth is running...')
})

app.listen(port, () => {
    console.log(`Server running on ${port}`)
})
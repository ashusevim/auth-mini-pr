import express, { type Request, type Response } from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcypt from "bcrypt";
import { users, type User } from "./users.js";
import jwt from "jsonwebtoken";
import { authenticate } from "./middleware/auth.js";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const jwt_secret = process.env.JWT_SECRET;

app.use(express.json());
app.use(cookieParser());

app.post("/signup", async (req: Request, res: Response) => {
	try {
		const { name, email, password, refreshToken } = req.body;

		// validate
		if (!name || !email || !password) {
			return res
				.status(400)
				.json({ message: "All the fields are required" });
		}

		// look for an existing user
		const existingUser = users.find((user) => user.email === email);

		if (existingUser) {
			return res.status(400).json({ message: "User already exists" });
		}

		// saltrounds shows how many times the hash is internally processed
		const saltRound = 10;
		const hashedPassword = await bcypt.hash(password, saltRound);

		// create an object for a new user
		const newUser: User = {
			id: users.length + 1,
			name,
			email,
			hashedPassword,
			refreshToken,
		};

		// push the new user to the in-memory demo database
		users.push(newUser);
		return res.status(201).json({
			message: "User registered successfully",
			userId: newUser.id,
		});
	} catch (error) {
		return res
			.status(500)
			.json({ message: "Error while registering user!!" });
	}
});

app.post("/login", async (req: Request, res: Response) => {
	try {
		const { email, password } = req.body;

		// validate input
		if (!(email || password)) {
			return res.status(400).json({
				message: "Email and password are required",
			});
		}

		// find user
		const user = users.find((user) => user.email === email);
		if (!user) {
			return res.status(404).json({
				message: "User not found!!",
			});
		}

		// it basically checks whether the password entered by the user mactches with the stored password
		const compare_password = await bcypt.compare(
			password,
			user.hashedPassword,
		);
		if (!compare_password) {
			return res.status(401).json({
				message: "Invalid credentials",
			});
		}

		// Generate access token (JWT)
		const token = jwt.sign(
			{ id: user.id, email: user.email },
			jwt_secret as string,
			{
				expiresIn: "15m",
			},
		);

		// Generate a refresh token (long lived)
		const refreshToken = jwt.sign(
			{ id: user.id, email: user.email },
			jwt_secret as string,
			{
				expiresIn: "7d",
			},
		);

		user.refreshToken = refreshToken;

		//send response
		return res.status(200).json({
			message: "Login successful",
			token, // short lived
			refreshToken, // long lived
		});
	} catch (error) {
		return res.status(500).json({
			message: "Error while login user"
		});
	}
});

app.get("/logout", (req: Request, res: Response) => {
	const { refreshToken } = req.body;
	const user = users.find((user) => user.refreshToken === refreshToken);
	if (user) user.refreshToken = "";
	return res.status(200).json({
		message: "Logged out successfully",
	});
});

app.get("/refresh", async (req: Request, res: Response) => {
	const { refreshToken } = req.body;

	if (!refreshToken) {
		return res.status(400).json({
			message: "Refresh token is required",
		});
	}

	// find the user who owns the refreshToken
	const user = users.find((user) => user.refreshToken === refreshToken);
	if (!user) {
		return res.status(403).json({
			message: "Invalid refresh token",
		});
	}

	try {
		jwt.verify(refreshToken, jwt_secret as string);

		const newAccessToken = jwt.sign(
			{ id: user.id, email: user.email },
			jwt_secret as string,
			{
				expiresIn: "15m",
			},
		);

		return res.status(200).json({
			message: "Token refreshed successfully",
			token: newAccessToken,
		});
	} catch (Error) {
		return res.status(403).json({
			message: "Expired or invalid refresh tokens",
		});
	}
});

app.get("/users", (req: Request, res: Response) => {
	return res.status(200).json({ users });
});

app.get("/users/:id", (req: Request, res: Response) => {
	try {
		const { id } = req.body;
		if (!id) {
			return res
				.status(400)
				.json({ message: "All the fields are required" });
		}

		const user = users.find(user => user.id === id);
		return res.status(200).json({ user });
	} catch (error) {
		return res.status(500).json({
			message: "Failed to find the user with the given ID",
		});
	}
});

app.post("/dashboard", authenticate, (req: Request, res: Response) => {
	// req.user is available and typed (refer to the types.d.ts)
	const user = req.user;
	return res.status(200).json({
		message: `Welcome to the dashboard,  ${user?.email}`,
	});
});

app.get("/", (req: Request, res: Response) => {
	res.send("Auth is running...");
});

app.listen(port, () => {
	console.log(`Server running on ${port}`);
});

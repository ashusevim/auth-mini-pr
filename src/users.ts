export interface User {
	id: number;
	name: string;
	email: string;
	hashedPassword: string;
	refreshToken: string;
}

// it will hold the "registered users"
export const users: User[] = [];

import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { User } from '../models/User.js';
import bcrypt from 'bcrypt';


//Helper to generate jwt Token
const generateToken = (id: string) => {
    return jwt.sign({id}, process.env.JWT_SECRET as string, {expiresIn:"30d"})
}

//Register a new user
//POST api/auth/register
export const registerUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, email, password, phone, role } = req.body;
        if(!email || !name || password) {
            res.status(400).json({message:"Please enter all required fields"})
            return;
        }
        //check if user exists
        const UserExists = await User.findOne({email});
        if (UserExists) {
            res.status(400).json({message: 'User already exists'})
            return;
        }
        //Hash password
        const salt = await bcrypt.genSalt(10)
        const hashedPassword = bcrypt.hash(password, salt)

        const user = await User.create({
            name,
            email,
            password: hashedPassword,
            phone,
            role
        })
    } catch (error) {}
}

//Authenticate a user and get token
//POST api/auth/login
export const loginUser = async (req: Request, res: Response): Promise<void> => {
    try {

    } catch (error) {}
}

//Get user profile
//GET api/auth/me
//@access private
export const getMe = async (req: Request, res: Response): Promise<void> => {
    try {

    } catch (error) {}
}
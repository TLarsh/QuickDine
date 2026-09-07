import {NextFunction, Request, Response} from "express";
import {IUser, User} from "../models/User.js";
import jwt from "jsonwebtoken";


export interface AuthenticatedRequest extends Request {
    user: IUser;
}

export const protect = (req: AuthenticatedRequest, res: Response, next: NextFunction): 
Promise<void> => {
    let token: string | undefined;
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        try {
            //Get token from header
            token = req.headers.authorization.split(" ")[1];
            //Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET) as {id: string};
            //Get user from token exclude password
            const user = await User.findById(decoded.id).select('-password');
            if (!user) {
                res.status(401).json({message: "Not authorized,user not found"});
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).json({message: "Not authorized, token failed"});
            return;
        }

            
    }    
}
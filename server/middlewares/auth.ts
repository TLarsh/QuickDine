import {NextFunction, Request, Response} from "express";
import {IUser} from "../models/User.js";
import jwt from "jsonwebtoken";


export interface AuthenticatedRequest extends Request {
    user: IUser;
}

export const protect = (req: AuthenticatedRequest, res: Response, next: NextFunction): 
Promise<void> => {
    let token: string | undefined;
    if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        token = req.headers.authorization.split(" ")[1];
    }

    if (!token) {
        res.status(401).json({message: "Not authorized, no token"});
        return;
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as {id: string};
        req.user = { _id: decoded.id } as IUser;
        next();
    } catch (error) {
        res.status(401).json({message: "Not authorized, token failed"});
    }
}
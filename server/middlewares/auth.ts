import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";
import { IUser, User } from "../models/User.js";

declare global {
  namespace Express {
    interface Request {
      user?: IUser;
    }
  }
}

export interface AuthenticatedRequest extends Request {
  user?: IUser;
}

export const protect = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
): Promise<void> => {
  const authorization = req.headers.authorization;

  if (!authorization || !authorization.startsWith("Bearer ")) {
    res.status(401).json({ message: "Not authorized, no token" });
    return;
  }

  try {
    const token = authorization.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET as string) as JwtPayload & { id?: string };

    if (!decoded?.id) {
      res.status(401).json({ message: "Not authorized, invalid token" });
      return;
    }

    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      res.status(401).json({ message: "Not authorized, user not found" });
      return;
    }

    req.user = user as IUser;
    next();
  } catch (error) {
    res.status(401).json({ message: "Not authorized, token failed" });
  }
};

export const adminOnly = () => {}
import { Request, Response } from "express";
import { logger } from "../../app";
import User, { passwordZodSchema, userZodSchema } from "./authModel";
import {
  sendErrorResponse,
  sendSuccessResponse,
} from "../../utils/standardReponse";
import bcrypt, { compare, hash } from "bcrypt";
import { sign } from "jsonwebtoken";
import { z } from "zod";

export async function registerController(req: Request, res: Response) {
  
  try {
    let { email, password } = userZodSchema.parse(req.body);
    //check if user exsists
    const ifExists = await User.find({ email: email });
    console.log(5555555555555555555);
    //if user exists, send res of user exists
    if (ifExists.length > 0) {
      sendErrorResponse(res, 409, "User already exists");
    }

    // hashing the password
    password = await bcrypt.hash(password, 10);



    //on verifying, save the user to database
    if (true) {
      const newUser = new User({ email: email, password: password });
      newUser.save();
      sendSuccessResponse(res, 200, "User registered successfully", newUser);
    } else {
      sendErrorResponse(res, 500, "", "failed to register user");
    }
  } catch (err) {
    if (err instanceof z.ZodError) {
      sendErrorResponse(res, 400, "Invalid Input", err.issues);
    }
    logger.error("Error registering  user with error message:" + err);
    sendErrorResponse(res, 500, "", err);
  }
}

export async function loginController(req: Request, res: Response) {
  try {
    // validating input
    const { email, password } = userZodSchema.parse(req.body);

    // checking if the user is registered in the database
    const user = await User.find({ email: email });

    console.log(user);

    if (user.length <= 0) {
      sendErrorResponse(res, 401, "Invalid Credentials");
    }

    // verifying password
    const validPassword = await compare(password, user[0].password!);
    if (!validPassword) {
      sendErrorResponse(res, 401, "Invalid Credentials");
    }


    // generating token
    const accessToken = sign(
      {
        id: user[0]._id,
      },
      process.env.JWT_SECRET_KEY!,
      { expiresIn: "45m" }
    );

    console.log("check 1")

    sendSuccessResponse(res, 201, "User logged in successfully", accessToken);
  } catch (error) {
    if (error instanceof z.ZodError) {
      sendErrorResponse(res, 400, "Invalid Input", error.issues);
    }
    logger.error("Login failed with the error:", error);
    sendErrorResponse(res, 500, "Internal Server Error", error);
  }
}

export async function profileController(req:Request, res:Response){
  try{
    const {id} = res.locals.payload;
    const user:any = await User.findById(id);
    if(!user){
      sendErrorResponse(res, 404, "User not found");
    }
    sendSuccessResponse(res, 200, "User retrieved successfully", {id: user._id, email: user.email });
  } catch(error){
    logger.error("Profile retrieval failed with the error:", error);
    sendErrorResponse(res, 500, "Internal Server Error", error);
  }
}

export async function refreshController(req:Request, res:Response){
  try{
    const {id} = res.locals.payload;
    const accessToken = sign(
      {
        id,
      },
      process.env.JWT_SECRET_KEY!,
      { expiresIn: "45m" }
    );
    
    sendSuccessResponse(res, 200, "Token refreshed successfully", accessToken);
  } catch(error){
    logger.error("failed to refresh token with the error:", error);
    sendErrorResponse(res, 500, "Internal Server Error", error);
  }
}


export async function resetPasswordsController(req:Request, res:Response){
  try{
    let {password} = passwordZodSchema.parse(req.body);
    const {id} = res.locals.payload;

    password = await hash(password, 10);

    const user = await User.findByIdAndUpdate(id, {password: password});

    sendSuccessResponse(res, 201, "Password reset done successfully", {});
  } catch(error){
    logger.error("failed to reset password with the error:"+ error);
    sendErrorResponse(res, 500, "Internal Server Error", error);
  }
}
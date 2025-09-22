import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { NextRequest, NextResponse } from "next/server";
import { db } from "../config/db";

export const Login = async (req:NextRequest) => {
    try {
        const { email, password} = await req.json();

        if(!password || !email) {
            return NextResponse.json({message: "Username and password are required"}, {status: 404});
        }
        const user = db.User.find({email})
        if(!user) return NextResponse.json({message: "User not found"});

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if(!isPasswordValid) return NextResponse.json({message: "Invalid password"}, {status: 401});

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET as string, { expiresIn: "1h" });

        return NextResponse.json({message: "Login successful"}, {status: 200});
    } catch (error) {
        return NextResponse.json({message: "Internal server error"}, {status: 500});
    }   
}

export const SignIn = async (req:NextRequest)=>{
    try {
        const { username, email, password} = await req.json();
        if(!username || !email || !password) {
            return NextResponse.json({message: "Username, email and password are required"});
        }
        const user = db.User.find({email})
        if(user) return NextResponse.json({message: "User already exists"});
        const hashedPassword = bcrypt.hashSync(password, 8);

        db.User.create({username, email, password: hashedPassword});
        
        return NextResponse.json({message: "User created successfully"});
    } catch (error) {
        return NextResponse.json({message: "Internal server error"});
    }
}
// import { Request, Response } from "express";
// import bcrypt from "bcryptjs";
// import jwt from "jsonwebtoken";
// import { JWT_SECRET } from "@repo/backend-common/config";
// import { CreateUserSchema, SigninSchema, CreateRoomSchema } from "@repo/common/config";
// import { db } from "../config/db";

// ✅ Login
// export const login = async (req: Request, res: Response) => {
//   try {
//     // Validate request body with Zod
//     const parsed = SigninSchema.safeParse(req.body);
//     if (!parsed.success) {
//       return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });
//     }

//     const { username, password } = parsed.data;

//     const user = await db.User.findOne({ where: { username } });
//     if (!user) return res.status(404).json({ message: "User not found" });

//     const isPasswordValid = bcrypt.compareSync(password, user.password);
//     if (!isPasswordValid) return res.status(401).json({ message: "Invalid password" });

//     const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "1h" });

//     return res.status(200).json({ message: "Login successful", token });
//   } catch (error) {
//     console.error("Login error:", error);
//     return res.status(500).json({ message: "Internal server error" });
//   }
// };

// // ✅ Sign Up (Register)
// export const signup = async (req: Request, res: Response) => {
//   try {
//     // Validate request body with Zod
//     const parsed = CreateUserSchema.safeParse(req.body);
//     if (!parsed.success) {
//       return res.status(400).json({ message: "Invalid input", errors: parsed.error.issues });
//     }

//     const { username, name, password } = parsed.data;

//     const existingUser = await db.User.findOne({ where: { username } });
//     if (existingUser) return res.status(409).json({ message: "User already exists" });

//     const hashedPassword = bcrypt.hashSync(password, 8);

//     await db.User.create({ username, name, password: hashedPassword });

//     return res.status(201).json({ message: "User created successfully" });
//   } catch (error) {
//     console.error("Signup error:", error);
//     return res.status(500).json({ message: "Internal server error" });
//   }
// };

// export const room = async (req: Request, res: Response)=>{
//   const data = CreateRoomSchema.safeParse(req.body);
//   if(!data.success){
//     return res.json({
//       message: "Incorrect Inputs",
//     })
//   }

//   res.json({
//     roomId: "1234",
//   })
//   return;
// }

export const login = ()=>{
  console.log("Login");

  return;
}
export const signup = ()=>{
  console.log("Login");

  return;
}
export const room = ()=>{
  console.log("Login");

  return;
}
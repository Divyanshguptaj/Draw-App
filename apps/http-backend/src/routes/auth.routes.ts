import express, { Router } from "express";
const router: Router = express.Router();

import { Login, SignIn } from "../controllers/auth.controller";

router.post("/login", Login);

router.post("/register", SignIn);

export default router;
import express, { Router } from "express";
const router: Router = express.Router();

import { login, signup } from "../controllers/auth.controller";

router.post("/login", login);

router.post("/register", signup);

export default router;
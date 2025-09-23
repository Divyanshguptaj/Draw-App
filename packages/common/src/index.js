"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CreateRoomSchema = exports.SigninSchema = exports.CreateUserSchema = void 0;
var zod_1 = require("zod");
exports.CreateUserSchema = zod_1.z.object({
    name: zod_1.z.string(),
    username: zod_1.z.string().min(3).max(20),
    password: zod_1.z.string().min(8),
});
exports.SigninSchema = zod_1.z.object({
    username: zod_1.z.string().min(3).max(20),
    password: zod_1.z.string().min(8),
});
exports.CreateRoomSchema = zod_1.z.object({
    name: zod_1.z.string().min(5).max(20),
});

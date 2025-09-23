import express from 'express';
import {CreateUserSchema} from "@repo/common/config"
import authRoutes from './routes/auth.routes';
const app = express();

app.use('/auth/api/v1', authRoutes);
app.use('/', ()=>{
    console.log("Inside ws-backend");
})

app.listen(3000, ()=>{
    console.log("Server is running on port 3000");
})
import dotenv from "dotenv";

dotenv.config();

if(!process.env.MONGO_URI){
    throw new Error("MONGO URI not initialized in environment variables");
}

if(!process.env.JWT_SECRET){
    throw new Error("JWT SECRET not initialized in environment variables");
}

if(!process.env.GOOGLE_CLIENT_ID){
    throw new Error("Google client id not initialized in environment variables");
}

if(!process.env.GOOGLE_CLIENT_SECRET){
    throw new Error("Google client secret not initialized in environment variables");
}

if(!process.env.GOOGLE_REFRESH_TOKEN){
    throw new Error("Google refresh token not initialized in environment variables");
}

if(!process.env.GOOGLE_ACCESS_TOKEN){
    throw new Error("Google access token not initialized in environment variables");
}

if(!process.env.GOOGLE_USER){
    throw new Error("Google user not initialized in environment variables");
}

const config = {
    MONGO_URI: process.env.MONGO_URI,
    JWT_SECRET: process.env.JWT_SECRET,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_REFRESH_TOKEN: process.env.GOOGLE_REFRESH_TOKEN,
    GOOGLE_ACCESS_TOKEN: process.env.GOOGLE_ACCESS_TOKEN,
    GOOGLE_USER: process.env.GOOGLE_USER,
}

export default config;
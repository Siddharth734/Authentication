import dotenv from "dotenv";

dotenv.config();

if(!process.env.MONGO_URI){
    throw new Error("MONGO URI not initialized in environment variables");
}

const config = {
    MONGO_URI: process.env.MONGO_URI,
}

export default config;
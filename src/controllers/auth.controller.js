import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import config from "../config/config.js";
import sessionModel from "../models/session.model.js";

export async function register(req, res) {

    const { username, email, password } = req.body;

    const isAlreadyRegistered = await userModel.findOne({
        $or: [
            { username },
            { email }
        ]
    })

    if (isAlreadyRegistered) {
        return res.status(409).json({
            message: "Username or email already exists"
        })
    }

    const hashedPass = crypto.createHash("sha256").update(password).digest("hex");

    const user = await userModel.create({
        username,
        email,
        password: hashedPass,
    })
    
    const refreshToken = jwt.sign({
        id: user._id
    }, config.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    )

    // sha256: deterministic hash function(same input -> same output)
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.create({
        user: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers[ "user-agent" ],

    })

    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session.id,
    }, config.JWT_SECRET,
        {
            expiresIn: "15m"
        }
    )

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true, //can't be accessed via js of browser
        secure: true, //true: https, http otherwise: https won't work for http://localhost
        sameSite: "strict", //cookie can't be sent cross-site
        maxAge: 7*24*60*60*1000 //7days
    })

    res.status(201).json({
        message: "User registered successfully",
        user:{
            username: username,
            email: email
        },
        accessToken,
    })
}

export async function login(req, res){
    const {username, password} = req.body;

    const user = await userModel.findOne({
        username
    })

    if(!user){
        return res.status(400).json({
            message: "Invalid username"
        })
    }
    
    const hashedPass = crypto.createHash("sha256").update(password).digest("hex");
    const validPassword = hashedPass === user.password; 
    if (!validPassword) {
        return res.status(400).json({
            message: "Invalid password"
        })
    }

    const refreshToken = jwt.sign({
        id: user._id,
    }, config.JWT_SECRET,
        {
            expiresIn: "7d"
        }
    )
    
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    
    const session = sessionModel.create({
        user: user._id,
        refreshTokenHash,
        ip: req.ip,
        userAgent: req.headers[ "user-agent" ]
    })

    const accessToken = jwt.sign({
        id: user._id,
        sessionId: session._id 
    }, config.JWT_SECRET,
        {
            expiresIn: "15m"
        }
    )

    res.cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7*24*60*60*100,
    })

    res.status(200).json({
        message: "logged in successfully",
        user:{
            username: user.username,
            email: user.emal,
        },
        accessToken,
    })
}

export async function getMe(req, res) {
    
    // .? will return if the named header does not exist
    const token = req.headers.authorization?.split(" ")[1];

    if(!token){
        return res.status(401).json({
            message: "token not found"
        })
    }

    const decoded = jwt.verify(token, config.JWT_SECRET);

    const user = await userModel.findById(decoded.id);

    res.status(200).json({
        message: "user found successfully",
        user: {
            username: user.username,
            email: user.email,
        }
    })
}

export async function refreshToken(req, res) {
    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message: "no refresh token was found"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false,
    })

    if(!session){
        return res.status(400).json({
            message: "Invalid refresh token"
        })
    }

    const accessToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET,
        {
            expiresIn: "15min"
        }
    )

    const newRefreshToken = jwt.sign({
        id: decoded.id
    }, config.JWT_SECRET,
        {
            expiresIn: "15min"
        }
    )

    session.refreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    await session.save();

    //additional layer of security
    res.cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 7*24*60*60*1000
    })

    res.status(200).json({
        message: "access token refreshed successfully",
        accessToken
    })
}

export async function logout(req, res) {
    
    const refreshToken = req.cookies.refreshToken;
     
    if(!refreshToken){
        return res.status(400).json({
            message: "refresh token not found"
        })
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked: false,
    })

    if(!session){
        return res.status(400).json({
            message: "invalid refresh token"
        })
    }

    session.revoked = true;
    await session.save();

    res.clearCookie("refreshToken");

    res.status(200).json({
        message: "Logged out successfully"
    })

}

export async function logoutAll(req, res){

    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(400).json({
            message: "invalid refresh token"
        })
    }

    const decoded = jwt.verify(refreshToken, config.JWT_SECRET);
    
    await sessionModel.updateMany({
        user: decoded.id,
        revoked: false,
    },{
        revoked: true
    })

    res.clearCookie("refreshToken");

    res.status(200).json({
        message: "Logged out from all device successfully"
    })
}
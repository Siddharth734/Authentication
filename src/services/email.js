import nodemailer from "nodemailer";
import config from "../config/config.js";

export const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        type: 'OAUTH2',
        user: config.GOOGLE_USER,
        clientId: config.GOOGLE_CLIENT_ID,
        clientSecret: config.GOOGLE_CLIENT_SECRET,
        refreshToken: config.GOOGLE_REFRESH_TOKEN,
    }
})

// to verify the connection configuration
transporter.verify((error, success) => {
    if(error){
        console.log("Error connecting to the email server:" + error)
    }
    else{
        console.log("Email is ready to send messages");
    }
});

export const sendEmail = async (to, subject, text, html) => {
    try {
        const info = await transporter.sendMail({
            from: `"Absolute-AUTH" <${config.GOOGLE_USER}>`,
            to, //list of receivers
            subject,
            text,
            html,
        });

        console.log('Message sent: %s', info.messageId);
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    } catch (error) {
        console.error('Error Sending email:', error);
    }
};
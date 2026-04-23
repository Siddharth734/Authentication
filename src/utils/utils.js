export function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

export function getOTPHTML(otp){
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OTP Verification</title>
    <style>
        body{
            background-color: whitesmoke;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .container{
            background-color: whitesmoke;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        .otp{
            font-size: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Your OTP Code</h2>
        <p>( Click to copy )</p>
        <a class="otp" href="#" onclick="copyOTP(event)">${otp}</a>
        <p>Use this to verify your email address.</p>
    </div>

    <script>
        function copyOTP(event) {
            event.preventDefault(); // prevents page jump

            const otp = event.target.innerText;
            navigator.clipboard.writeText(otp);
        }
    </script>
</body>
</html>`
}
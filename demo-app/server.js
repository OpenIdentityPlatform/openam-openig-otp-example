const express = require("express");
const app = express();
const port = 3000;


// Set EJS as the view engine
app.set("view engine", "ejs");

// Profile Page Route
app.get("/", (req, res) => {
    console.log("got request", req.headers)
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send("Unauthorized");
    }
    const jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    const user = { name: jwtPayload.sub };
    res.render("profile", { user });
});

// Sensitive Data Page Route (Protected)
app.get("/sensitive", (req, res) => {
    console.log("got sensitive data request")
    const sensitiveData = { bankAccount: "1234-5678-9012", secretKey: "ABCD-EFGH" };
    res.render("sensitive", { sensitiveData });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
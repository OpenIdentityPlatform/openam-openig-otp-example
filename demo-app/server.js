const express = require("express");
const app = express();
const port = 3000;


// Set EJS as the view engine
app.set("view engine", "ejs");

app.use((req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send("Unauthorized");
    }
    next()
})

// Profile Page Route
app.get("/", (req, res) => {
    const jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    const user = { name: jwtPayload.sub };
    res.render("profile", { user });
});

// Sensitive Data Page Route (Protected)
app.get("/sensitive", (req, res) => {
    const sensitiveData = { bankAccount: "1234-5678-9012-3456", secretKey: "MY_SUPER_SECRET_KEY" };
    res.render("sensitive", { sensitiveData });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
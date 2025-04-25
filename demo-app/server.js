const express = require("express");
const app = express();
const port = 3000;

app.set("view engine", "ejs");

app.use((req, res, next) => {
    console.log(req.headers)
    const token = req.headers.authorization;
    if (!token) {
        return res.status(401).send("Unauthorized");
    }
    next()
})

app.get("/", (req, res) => {
    const token = req.headers.authorization;
    const jwtPayload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    const user = { name: jwtPayload.sub };
    res.render("profile", { user });
});

app.get("/sensitive", (req, res) => {
    const sensitiveData = { bankAccount: "1234-5678-9012-3456", secretKey: "MY_SUPER_SECRET_KEY" };
    res.render("sensitive", { sensitiveData });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
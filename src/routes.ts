import express from "express";
import db from "./dbConfig";
import bcrypt from "bcrypt";

const router = express.Router();

function findUser(email: string) {
  const results = db.data.users.filter((user) => user.email === email);
  if (results.length === 0) {
    return undefined;
  }

  return results[0];
}

router.get("/users", (req, res) => {
  const data = db.data;
  return res.json(data);
});

router.post("/auth/login", (req, res) => {
  const user = findUser(req.body.email);
  if (user) {
    // user exists, check password
    if (bcrypt.compareSync(req.body.password, user.password)) {
      res.send({ ok: true, email: user.email, name: user.name });
    } else {
      res.send({ ok: false, message: "Data is invalid" });
    }
  } else {
    // User doesn't exist
    res.send({ ok: false, message: "Data is invalid" });
  }
});

export default router;

import express from "express";
import db, { User } from "./dbConfig";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import { JwtPayload, jwtDecode } from "jwt-decode";

interface Auth0JwtPayload extends JwtPayload {
  picture: string;
  given_name: string;
  family_name: string;
  email: string;
}

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
  return res.json(data.users);
});

router.get("/user/:id", (req, res) => {
  const userId = req.params.id;
  const users = db.data.users;

  const userFound = users.find((user) => user.id === userId);

  if (userFound) {
    res.send({
      ok: true,
      user: {
        name: userFound.name,
        email: userFound.email,
      },
    });
  } else {
    res.send({ ok: false, message: "Data is invalid" });
  }
});

router.post("/auth/login", (req, res) => {
  const user = findUser(req.body.email);
  if (user) {
    // user exists, check password
    if (bcrypt.compareSync(req.body.password, user.password)) {
      res.send({ ok: true, userId: user.id });
    } else {
      res.send({ ok: false, message: "Data is invalid" });
    }
  } else {
    // User doesn't exist
    res.send({ ok: false, message: "Data is invalid" });
  }
});

router.post("/auth/login-google", (req, res) => {
  const decoded = jwtDecode<Auth0JwtPayload>(req.body.credential);

  const user: Omit<User, "id" | "federated"> = {
    name: `${decoded.given_name} ${decoded.family_name}`,
    email: decoded.email,
    password: "",
  };

  const userFound = findUser(user.email);

  if (userFound) {
    // User exists, we update it with the Google data
    userFound.federated.google = decoded.aud;
    db.write();
    res.send({ ok: true, userId: userFound.id });
  } else {
    // User doesn't exist we create it
    const newUser = {
      ...user,
      id: uuidv4(),
      federated: {
        google: decoded.aud,
      },
    };
    db.data.users.push(newUser);
    db.write();
    res.send({ ok: true, userId: newUser.id });
  }
});

router.post("/auth/register", (req, res) => {
  var salt = bcrypt.genSaltSync(10);
  var hash = bcrypt.hashSync(req.body.password, salt);

  const user = {
    name: req.body.name,
    email: req.body.email,
    password: hash,
    federated: {},
  };
  const userFound = findUser(req.body.email);

  if (userFound) {
    // User already registered
    res.send({ ok: false, message: "User already exists" });
  } else {
    // New User
    const newUser = {
      ...user,
      id: uuidv4(),
    };
    db.data.users.push(newUser);
    db.write();
    res.send({ ok: true, userId: newUser.id });
  }
});

export default router;

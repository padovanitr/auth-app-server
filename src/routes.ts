import express from "express";
import db, { User } from "./dbConfig";
import bcrypt from "bcrypt";
import { v4 as uuidv4 } from "uuid";
import { JwtPayload, jwtDecode } from "jwt-decode";
import {
  GenerateRegistrationOptionsOpts,
  VerifyRegistrationResponseOpts,
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

export const rpID = "localhost";

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

router.post("/auth/auth-options", (req, res) => {
  console.log("req.body.email", req.body.email);
  const user = findUser(req.body.email);
  console.log("user", user);

  if (user) {
    const userOptions = {
      password: !!user.password,
      google: user.federated && user.federated.google,
      webauthn: user.webAuthn,
    };
    console.log("userOptions", userOptions);

    res.send(userOptions);
  } else {
    res.send({
      password: true,
    });
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

// WEBAUTHAN ENDPOINTS

router.post("/auth/webauth-registration-options", async (req, res) => {
  const user = findUser(req.body.email);

  if (user) {
    const options: GenerateRegistrationOptionsOpts = {
      rpName: "Auth app",
      rpID,
      userID: user.email,
      userName: user.name,
      timeout: 60000,
      attestationType: "none",

      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      excludeCredentials:
        user && user.devices
          ? user.devices.map((dev) => ({
              id: dev.credentialID as unknown as BufferSource,
              type: "public-key",
              transports: dev.transports as unknown as AuthenticatorTransport[],
            }))
          : [],

      authenticatorSelection: {
        userVerification: "required",
        residentKey: "required",
      },
      /**
       * The two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
    };

    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    const regOptions = await generateRegistrationOptions(options);

    if (regOptions) {
      console.log("entrou aqui no user");
      user.currentChallenge = regOptions.challenge;
      db.write();
      res.send(regOptions);
    } else {
      res.send({
        ok: false,
        message: "Something went wrong, please try again",
      });
    }
  } else {
    res.send({ ok: false, message: "Something went wrong, please try again" });
  }
});

router.post("/auth/webauth-registration-verification", async (req, res) => {
  const user = findUser(req.body.user.email);
  const data = req.body.data;

  const response = {
    id: data.id,
    rawId: data.rawId,
    response: data.response,
    clientExtensionResults: data.clientExtensionResults,
    type: data.type,
  };

  if (user) {
    const expectedChallenge = user.currentChallenge;

    let verification;
    try {
      const options: VerifyRegistrationResponseOpts = {
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin: "http://localhost:3001",
        expectedRPID: rpID,
        requireUserVerification: true,
        response: response,
      };
      verification = await verifyRegistrationResponse(options);
      console.log("verification", verification);
    } catch (error) {
      console.log(error);
      return res.status(400).send({ error });
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      const existingDevice = user.devices
        ? user.devices.find((device) =>
            Buffer.from(device.credentialID as Buffer).equals(credentialID)
          )
        : false;

      if (!existingDevice) {
        const newDevice = {
          credentialPublicKey,
          credentialID,
          counter,
          transports: data.response.transports,
        };

        if (user.devices == undefined) {
          user.devices = [];
        }
        user.webAuthn = true;
        user.devices.push(newDevice);
        db.write();
      }
    }

    res.send({ ok: true });
  } else {
    res.send({ ok: false, message: "Something went wrong, please try again" });
  }
});

export default router;

import express from "express";
import cors from "cors";
import db from "./dbConfig";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 4000;

app.get("/users", (req, res) => {
  const data = db.data;
  return res.json(data);
});

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);

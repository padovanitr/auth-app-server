import express from "express";
import cors from "cors";
import router from "./routes";

const app = express();

app.use(cors());
app.use(express.json());

const PORT = 4000;

app.use("/api", router);

app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);

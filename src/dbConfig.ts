import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { LowSync } from "lowdb";
import { JSONFileSync } from "lowdb/node";

interface Clients {
  key: string;
  status: boolean;
  username: string;
  password: string;
}

interface Status {
  key: string;
  username: string;
  status: "UP" | "DOWN" | "COOLING" | "SUSPENDED";
}

interface Database {
  clients: Array<Clients>;
  status: Array<Status>;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const file = join(__dirname, "./db.json");

const adapter = new JSONFileSync<Database>(file);
const db = new LowSync(adapter, {
  clients: [],
  status: [],
});

db.read();

db.data ||= { clients: [], status: [] };

if (db.data.clients.length === 0) {
  db.data.clients.push({
    key: "1",
    status: true,
    username: "dummyuser",
    password: "dummypw",
  });
}

db.write();

export default db;

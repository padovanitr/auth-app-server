import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { LowSync } from "lowdb";
import { JSONFileSync } from "lowdb/node";

interface User {
  id: string;
  name: string;
  email: string;
  password: string;
}

interface Database {
  users: Array<User>;
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const file = join(__dirname, "../db.json");

const adapter = new JSONFileSync<Database>(file);
const db = new LowSync(adapter, {
  users: [],
});

db.read();

db.data ||= { users: [] };

/* if (db.data.clients.length === 0) {
  db.data.clients.push({
    key: "1",
    status: true,
    username: "dummyuser",
    password: "dummypw",
  });
} */

db.write();

export default db;

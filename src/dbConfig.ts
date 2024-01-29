import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { LowSync } from "lowdb";
import { JSONFileSync } from "lowdb/node";

type DeviceType = {
  credentialID: unknown;
  transports: string;
  credentialPublicKey: unknown;
  counter: unknown;
};

export interface User {
  id: string;
  name: string;
  email: string;
  password: string;
  federated: {
    google?: string | string[];
  };
  webAuthn?: unknown;
  devices?: DeviceType[];
  currentChallenge?: string;
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

db.write();

export default db;

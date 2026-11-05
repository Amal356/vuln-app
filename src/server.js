// TP10 : vuln-app CORRIGÉE après analyse Semgrep (partie 3).
// Chaque bloc [FIX] remplace un bloc [VULN] de la version d'origine.
const express = require("express");
const { execFile } = require("child_process");
const sqlite3 = require("sqlite3");
const jwt = require("jsonwebtoken");
const _ = require("lodash");
const config = require("./config");

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "10kb" }));

const db = new sqlite3.Database(":memory:");
db.serialize(() => {
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)");
  db.run("INSERT INTO users (name, role) VALUES ('alice', 'admin'), ('bob', 'user')");
});

/** Échappe les caractères HTML spéciaux (protection XSS). */
function escapeHtml(value) {
  const map = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value).replace(/[&<>"']/g, (c) => map[c]);
}

// [FIX] Injection SQL : requête PARAMÉTRÉE, la valeur n'est jamais concaténée au SQL.
//       L'erreur SQL n'est plus renvoyée au client.
app.get("/users", (req, res) => {
  const name = String(req.query.name ?? "");
  db.all("SELECT id, name FROM users WHERE name = ?", [name], (err, rows) =>
    err ? res.status(500).json({ error: "INTERNAL_ERROR" }) : res.json(rows)
  );
});

// [FIX] Injection de commande : execFile (pas de shell) + liste blanche stricte du nom d'hôte.
const HOSTNAME = /^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$/; // pas d'espace, de ; | & $ ` ni de "-" initial
app.get("/ping", (req, res) => {
  const host = String(req.query.host ?? "");
  if (!HOSTNAME.test(host)) return res.status(400).json({ error: "INVALID_HOST" });
  execFile("ping", ["-c", "1", host], { timeout: 5000 }, (err, stdout) =>
    res.type("text").send(err ? "ping impossible" : stdout)
  );
});

// [FIX] XSS réfléchi : l'entrée est échappée avant d'être insérée dans le HTML.
app.get("/hello", (req, res) => {
  const name = escapeHtml(req.query.name ?? "");
  // nosemgrep: javascript.express.security.audit.xss.direct-response-write.direct-response-write
  res.type("html").send(`<h1>Bonjour ${name}</h1>`); // nosemgrep: javascript.express.security.injection.raw-html-format.raw-html-format -- valeur échappée par escapeHtml()
});

// [FIX] Prototype pollution : on ne fusionne plus l'objet client, on ne garde que des champs autorisés
//       (lodash est aussi mis à jour en 4.17.21 dans la partie 4).
app.post("/settings", (req, res) => {
  const settings = _.pick(req.body ?? {}, ["theme", "lang"]);
  res.json(settings);
});

// [FIX] JWT : secret lu dans l'environnement (config.js), algorithme imposé, expiration courte.
app.post("/login", (req, res) => {
  const user = String(req.body?.user ?? "");
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(user)) return res.status(400).json({ error: "INVALID_USER" });
  const token = jwt.sign({ user, role: "user" }, config.jwt_secret, { algorithm: "HS256", expiresIn: "15m" });
  res.json({ token });
});

app.listen(config.port, () => console.log(`vuln-app écoute sur ${config.port}`));

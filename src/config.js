// Les secrets ne sont plus dans le code : ils viennent de l'environnement (.env non versionné).
function required(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Variable d'environnement manquante : ${name}`);
  return value;
}

module.exports = {
  port: Number(process.env.PORT ?? 3000),
  jwt_secret: required("JWT_SECRET"),
  payment_api_key: required("PAYMENT_API_KEY"),
  db_password: required("DB_PASSWORD"),
};

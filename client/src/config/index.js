import runtimeConfig from "./runtime";

class Config {
  constructor() {
    this.apiBase = runtimeConfig.apiBase;
    this.firebase = runtimeConfig.firebase;

    this.isDevelopment = import.meta.env.DEV;
    this.isProduction = import.meta.env.PROD;
    this.mode = import.meta.env.MODE;

    this._validate();
  }

  _getEnv(key, defaultValue = "") {
    const value = import.meta.env[key];
    return value !== undefined ? value : defaultValue;
  }

  _validate() {
    const requiredFirebaseKeys = [
      "apiKey",
      "authDomain",
      "projectId",
      "storageBucket",
      "messagingSenderId",
      "appId",
    ];

    const missingKeys = [];

    for (const key of requiredFirebaseKeys) {
      if (
        !this.firebase[key] ||
        this.firebase[key] === "your-api-key-here" ||
        this.firebase[key] === "your-project-id" ||
        this.firebase[key].includes("your-")
      ) {
        missingKeys.push(key);
      }
    }

    if (missingKeys.length > 0 && this.isProduction) {
      console.error(
        `Missing or invalid Firebase configuration: ${missingKeys.join(", ")}\n` +
          "Please set these environment variables.",
      );
      throw new Error(
        `Invalid Firebase configuration. Required keys: ${missingKeys.join(", ")}`,
      );
    }

    if (missingKeys.length > 0 && this.isDevelopment) {
      console.warn(
        `Warning: Missing or invalid Firebase configuration: ${missingKeys.join(", ")}\n` +
          "Firebase authentication may not work correctly.",
      );
    }
  }

  getFirebaseConfig() {
    return { ...this.firebase };
  }

  getApiBase() {
    return this.apiBase;
  }

  isDev() {
    return this.isDevelopment;
  }

  isProd() {
    return this.isProduction;
  }

  logConfig() {
    if (this.isDevelopment) {
      console.log("Application Configuration:", {
        mode: this.mode,
        apiBase: this.apiBase,
        firebase: {
          projectId: this.firebase.projectId,
          authDomain: this.firebase.authDomain,
        },
      });
    }
  }
}

const config = new Config();

if (config.isDevelopment) {
  config.logConfig();
}

export default config;

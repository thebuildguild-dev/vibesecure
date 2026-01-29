function getRuntimeConfig() {
  if (window.__APP_CONFIG__) {
    return window.__APP_CONFIG__;
  }

  return {
    apiBase: import.meta.env.VITE_API_BASE || "/api",
    firebase: {
      apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
      authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
      projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
      storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
      messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
      appId: import.meta.env.VITE_FIREBASE_APP_ID,
    },
  };
}

export default getRuntimeConfig();

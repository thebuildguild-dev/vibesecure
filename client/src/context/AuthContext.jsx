import { createContext, useContext, useState, useEffect } from "react";
import {
  signInWithPopup,
  signOut as firebaseSignOut,
  onAuthStateChanged,
} from "firebase/auth";
import { auth, googleProvider } from "../firebase";
import { auth as authAPI } from "../api/client";

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      if (firebaseUser) {
        try {
          const idToken = await firebaseUser.getIdToken();
          setUser(firebaseUser);

          try {
            await authAPI.login(idToken);

            const profileData = await authAPI.getProfile();
            setProfile(profileData);
          } catch (err) {
            console.error("Error during login/profile fetch:", err);
            setError(err.message);
          }
        } catch (err) {
          console.error("Error getting token:", err);
          setError(err.message);
        }
      } else {
        setUser(null);
        setProfile(null);
      }
      setLoading(false);
    });

    const tokenRefreshInterval = setInterval(
      async () => {
        if (auth.currentUser) {
          try {
            const freshToken = await auth.currentUser.getIdToken(true);
            await authAPI.login(freshToken);
          } catch (err) {
            console.error("Error refreshing token:", err);
          }
        }
      },
      50 * 60 * 1000, // 50 minutes
    );

    return () => {
      unsubscribe();
      clearInterval(tokenRefreshInterval);
    };
  }, []);

  const signInWithGoogle = async () => {
    setError(null);
    setLoading(true);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      const idToken = await result.user.getIdToken();

      await authAPI.login(idToken);

      return result.user;
    } catch (err) {
      console.error("Google sign-in error:", err);
      setError(err.message);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const signOut = async () => {
    setError(null);
    try {
      await authAPI.logout();

      await firebaseSignOut(auth);
    } catch (err) {
      console.error("Sign out error:", err);
      setError(err.message);
      throw err;
    }
  };

  const value = {
    user,
    profile,
    loading,
    error,
    signInWithGoogle,
    signOut,
    isAuthenticated: !!user,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

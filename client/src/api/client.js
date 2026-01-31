import config from "../config";

const API_BASE = config.getApiBase();

class APIError extends Error {
  constructor(message, status, errorType) {
    super(message);
    this.status = status;
    this.errorType = errorType;
  }
}

async function fetchWithAuth(endpoint, options = {}) {
  const { responseType, timeout = 10000, ...fetchOptions } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  const headers = {
    "Content-Type": "application/json",
    ...fetchOptions.headers,
  };

  try {
    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...fetchOptions,
      headers,
      credentials: "include",
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));

      if (response.status === 403) {
        const errorType = errorData.detail?.type || errorData.type;
        throw new APIError(
          errorData.detail?.message || errorData.message || "Forbidden",
          403,
          errorType,
        );
      }

      let errorMessage = "Request failed";
      if (typeof errorData.detail === "object" && errorData.detail !== null) {
        errorMessage =
          errorData.detail.message || JSON.stringify(errorData.detail);
      } else if (typeof errorData.detail === "string") {
        errorMessage = errorData.detail;
      } else if (errorData.message) {
        errorMessage = errorData.message;
      }

      throw new APIError(
        errorMessage,
        response.status,
        errorData.detail?.error,
      );
    }

    if (responseType === "blob") {
      return response.blob();
    }

    return response.json();
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("Request timed out");
    }
    throw error;
  } finally {
    clearTimeout(id);
  }
}

export const auth = {
  login: (firebaseToken) =>
    fetchWithAuth("/auth/login", {
      method: "POST",
      body: JSON.stringify({ firebase_token: firebaseToken }),
    }),

  logout: () =>
    fetchWithAuth("/auth/logout", {
      method: "POST",
    }),

  getProfile: () => fetchWithAuth("/auth/profile"),
};

export const domains = {
  getStatus: (domain) =>
    fetchWithAuth(`/domains/${encodeURIComponent(domain)}/status`),

  list: () => fetchWithAuth("/domains/list"),

  requestVerification: (domain) =>
    fetchWithAuth("/domains/verify/request", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),

  checkVerification: (domain, verificationId = null) =>
    fetchWithAuth("/domains/verify/check", {
      method: "POST",
      body: JSON.stringify({ domain, verification_id: verificationId }),
    }),

  deleteVerificationRequest: (domain) =>
    fetchWithAuth(
      `/domains/verify/request?domain=${encodeURIComponent(domain)}`,
      {
        method: "DELETE",
      },
    ),
};

export const consent = {
  getStatus: (domain) =>
    fetchWithAuth(`/consent/${encodeURIComponent(domain)}/status`),

  list: () => fetchWithAuth("/consent/list"),

  request: (domain) =>
    fetchWithAuth("/consent/request", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),

  check: (domain) =>
    fetchWithAuth("/consent/check", {
      method: "POST",
      body: JSON.stringify({ domain }),
    }),
};

export const scans = {
  create: (url, description = null, options = null) =>
    fetchWithAuth("/scans", {
      method: "POST",
      body: JSON.stringify({ url, description, options }),
    }),

  list: (skip = 0, limit = 20) =>
    fetchWithAuth(`/scans?skip=${skip}&limit=${limit}`),

  get: (scanId) => fetchWithAuth(`/scans/${scanId}`),

  getFindings: (scanId) => fetchWithAuth(`/scans/${scanId}/findings`),

  getReport: (scanId, format = "json") =>
    fetchWithAuth(`/scans/${scanId}/report?format=${format}`, {
      responseType: format === "pdf" ? "blob" : "json",
    }),

  getAISummary: (scanId) => fetchWithAuth(`/scans/${scanId}/ai-summary`),

  getFixConfig: (scanId, platform) =>
    fetchWithAuth(`/scans/${scanId}/fix-config?platform=${platform}`),
};

export { APIError };

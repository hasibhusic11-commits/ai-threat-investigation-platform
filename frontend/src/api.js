import axios from "axios";

const api = axios.create({
  baseURL: "http://127.0.0.1:8000",
});

api.interceptors.request.use((config) => {
  const apiKey = localStorage.getItem("backend_api_key");
  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  }
  return config;
});

export default api;

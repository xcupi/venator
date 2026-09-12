import axios from "axios";

const BACKEND = process.env.REACT_APP_BACKEND_URL || "";
export const api = axios.create({ baseURL: `${BACKEND}/api` });

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("xss_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem("xss_token");
      if (!window.location.pathname.endsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(err);
  },
);

export const login = async (email, password) => {
  const { data } = await api.post("/auth/login-json", { email, password });
  localStorage.setItem("xss_token", data.access_token);
  return data;
};

export const logout = () => {
  localStorage.removeItem("xss_token");
  window.location.href = "/login";
};

export const isAuthed = () => Boolean(localStorage.getItem("xss_token"));

import axios from "axios";

const api = axios.create({
    baseURL: "http://localhost:5000/api",
});

api.interceptors.request.use((config) => {
    const token = sessionStorage.getItem("access_token"); // 👈 MATCHES YOUR LOGIN

    if (token) {
        config.headers.Authorization = `Bearer ${token}`;
    }

    return config;
});

export default api;
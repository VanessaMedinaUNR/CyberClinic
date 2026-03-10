import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const api = axios.create({baseURL: process.env.REACT_APP_BACKEND_SERVER + "/api"})
api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem("access_token");
    if (token) {
        config.headers["Authorization"] = 'Bearer ' + token;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
    (res) => {
        return(res)
    },
    async (error) => {
        const origConf = error.config;
        if (origConf.url !== "/auth/login" && error.response) {
            console.log(error.response);
            if (error.response.data.code === 'fresh_token_required') {
                sessionStorage.setItem('access_token', '');
                sessionStorage.setItem('refresh_token', '');
                return window.location.href = "/login";
             }
            if (error.response.status === 403 && !origConf._retry) {
                origConf._retry = true;

                try {
                    const refresh = sessionStorage.getItem('refresh_token');

                    if (refresh){
                        sessionStorage.setItem('access_token', refresh);
                        const rs = await api.post("/auth/refresh");
                        
                        const { access_token } = rs.data;
                        sessionStorage.setItem('access_token', access_token);
                        sessionStorage.setItem('refresh_token', '');
                    }
                    return api(origConf);
                } catch (_error)
                {
                    console.log(_error)
                    return Promise.reject(error);
                }
            } else if (error.response.status === 403) {
                sessionStorage.setItem('access_token', '');
                sessionStorage.setItem('refresh_token', '');
                return window.location.href = "/login";
            }
        }
        return Promise.reject(error);
    }
);

export default api;
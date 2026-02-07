import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const api = axios.create({baseURL: process.env.REACT_APP_BACKEND_SERVER + "/api"})
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("access_token");
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
            console.log(error.response)
            if (error.response.data.code === 'fresh_token_required') {
                localStorage.setItem('access_token', '');
                localStorage.setItem('refresh_token', '') 
                return Promise.reject(error);
             }
            if (error.response.status === 401 && !origConf._retry) {
                origConf._retry = true;

                try {
                    const refresh = localStorage.getItem('refresh_token');

                    if (refresh){
                        localStorage.setItem('access_token', refresh)
                        const rs = await api.post("/auth/refresh");
                        
                        const { access_token } = rs.data;
                        localStorage.setItem('access_token', access_token);
                        localStorage.setItem('refresh_token', '');
                    }
                    return api(origConf);
                } catch (_error)
                {
                    console.log(_error)
                    return Promise.reject(error);
                }
            }
        }
        return Promise.reject(error);
    }
);

export default api;
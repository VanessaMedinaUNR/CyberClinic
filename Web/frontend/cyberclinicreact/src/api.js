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
        return new Promise((resolve, reject) => {
            const origConf = error.config;
            if (origConf.url !== "/auth/login" && error.response) {
                console.log(error.response);
                if (error.response.status === 401) {
                    if (error.response.data.code === 'fresh_token_required') {
                        sessionStorage.removeItem('access_token');
                        sessionStorage.removeItem('refresh_token');
                    }
                    reject(error);
                } else if (error.response.status === 403 && !origConf._retry) {
                    origConf._retry = true;
                    const refresh = sessionStorage.getItem('refresh_token');
    
                    if (refresh){
                        console.log("Attempting to refresh access token using refresh token...");
                        sessionStorage.setItem('access_token', refresh);
                        api.post("/auth/refresh").then(function (rs) {
                            const { access_token, refresh_token } = rs.data;
                            console.log("Access token refreshed successfully!");
                            sessionStorage.setItem('access_token', access_token);
                            sessionStorage.setItem('refresh_token', refresh_token);
                            origConf.headers['Authorization'] = 'Bearer ' + access_token;
                        }).catch(function (err) {
                            sessionStorage.removeItem('access_token');
                            sessionStorage.removeItem('refresh_token');
                            console.log(err);
                            reject(err);
                        });
                    } else {
                        sessionStorage.removeItem('access_token');
                        sessionStorage.removeItem('refresh_token');
                        reject(error);
                    }
                    console.log("Retrying original request with new access token...");
                    api(origConf).then(function (response) {
                        console.log(response)
                        resolve(response);
                    }).catch(function (err) {
                        console.log("Error retrying original request:", err);
                        reject(err);
                    });
                } else if (error.response.status === 403) {
                    sessionStorage.removeItem('access_token');
                    sessionStorage.removeItem('refresh_token');
                    reject(error);
                }
            }
            reject(error);
        });
    }
);

export default api;
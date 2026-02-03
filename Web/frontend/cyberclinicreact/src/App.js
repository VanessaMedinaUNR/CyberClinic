import AppRoutes from './routes';
import axios from 'axios';

import './login.css';

function App() {
    return(
        <>
            <AppRoutes />
        </>  
    );
}

export default App;

//Function to add authorization header to axios requests
export const setAuthToken = token => {
   if (token) {
       axios.defaults.headers.common["Authorization"] = `Bearer ${token}`;
   }
   else
       delete axios.defaults.headers.common["Authorization"];
}

//Update token from local storage
const token = localStorage.getItem("access_token");
if (token) {
    setAuthToken(token);
}
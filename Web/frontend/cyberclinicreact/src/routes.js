import { Routes, Route } from "react-router-dom";
import Forgotpw from "./forgotpw";
import Login from "./login";
import Signup from "./signup";
import NewScan from "./newscan";

export default function AppRoutes() {
    return (
        <Routes>
            <Route path="/" element={<Login />} />
            <Route path="/forgotpw" element={<Forgotpw />} />
            <Route path="/signup" element ={<Signup/>} />
            <Route path="/newscan" element ={<Signup/>} />
        </Routes>
    );
}
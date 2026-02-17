import { Routes, Route } from "react-router-dom";
import Forgotpw from "./forgotpw";
import Login from "./login";
import Signup from "./signup";
import NewScan from "./newscan";
import Dashboard from "./dashboard";
import Setting from "./setting";
import NewTarget from './newtarget';
import CodeChecker from './codechecker';

//make sure the import... is cap

export default function AppRoutes() {
    return (
        <Routes>
            <Route path="/" element={<Login />} />
            <Route path="/forgotpw" element={<Forgotpw />} />
            <Route path="/signup" element ={<Signup/>} />
            <Route path="/newscan" element ={<NewScan/>} /> {/*it was saying Signup instead of newscan*/}
            <Route path="/newtarget" element ={<NewTarget/>} />
            <Route path="/dashboard" element ={<Dashboard/>} />
            <Route path="/setting" element ={<Setting/>} />
            <Route path="/codechecker" element ={<CodeChecker/>} />
        </Routes>
    );
}
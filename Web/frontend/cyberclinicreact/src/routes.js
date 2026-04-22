import { Routes, Route } from "react-router-dom";
import Forgotpw from "./forgotpw";
import Login from "./login";
import Signup from "./signup";
import NewScan from "./newscan";
import Dashboard from "./dashboard";
import Setting from "./setting";
import NewTarget from './newtarget';
import CodeChecker from './codechecker';
import ReportViewer from "./report";
import AdminDashboard from "./admindashboard"
import Home from "./home";
import Faq from "./faq";

//make sure the import... is cap

export default function AppRoutes() {
    return (
        <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/forgotpw" element={<Forgotpw />} />
            <Route path="/signup" element ={<Signup/>} />
            <Route path="/newscan" element ={<NewScan/>} /> {/*it was saying Signup instead of newscan*/}
            <Route path="/newtarget" element ={<NewTarget/>} />
            <Route path="/dashboard" element ={<Dashboard/>} />
            <Route path="/setting" element ={<Setting/>} />
            <Route path="/codechecker" element ={<CodeChecker/>} />
            <Route path="/faq" element ={<Faq/>} />
            <Route path="/report" element ={<ReportViewer/>} />
            <Route path="/admin" element ={<AdminDashboard/>} />
        </Routes>
    );
}
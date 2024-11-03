// src/App.js
import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Login from "./Login";
import Register from "./Register";
import AddProduct from "./AddProduct";
import ViewProducts from "./ViewProducts";
import BuyProduct from "./BuyProduct";
import Bill from "./Bill";
import Navbar from "./Navbar";
import "./App.css";

const App = () => {
  const [role, setRole] = useState(null);
  const [token, setToken] = useState(null);

  const handleLogout = () => {
    setRole(null);
    setToken(null);
  };

  return (
    <Router>
      <Navbar role={role} token={token} handleLogout={handleLogout} />
      <Routes>
        <Route path="/" element={<Navigate to={token ? (role === "seller" ? "/add-product" : "/buy-product") : "/login"} />} />
        <Route path="/login" element={token ? <Navigate to={role === "seller" ? "/add-product" : "/buy-product"} /> : <Login setRole={setRole} setToken={setToken} />} />
        <Route path="/register" element={<Register />} />
        <Route path="/add-product" element={token && role === "seller" ? <AddProduct token={token} /> : <Navigate to="/login" />} />
        <Route path="/view-products" element={token && role === "seller" ? <ViewProducts token={token} /> : <Navigate to="/login" />} />
        <Route path="/buy-product" element={token && role === "customer" ? <BuyProduct token={token} /> : <Navigate to="/login" />} />
        <Route path="/bill" element={token ? <Bill /> : <Navigate to="/login" />} />
      </Routes>
    </Router>
  );
};

export default App;

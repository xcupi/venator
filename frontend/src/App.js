import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import "@/App.css";
import Sidebar from "@/components/Sidebar";
import Dashboard from "@/pages/Dashboard";
import Projects from "@/pages/Projects";
import Scans from "@/pages/Scans";
import ScanDetail from "@/pages/ScanDetail";
import Findings from "@/pages/Findings";
import AuthProfiles from "@/pages/AuthProfiles";
import Login from "@/pages/Login";
import { isAuthed } from "@/lib/api";

const Protected = ({ children }) => (isAuthed() ? children : <Navigate to="/login" replace />);

const Shell = ({ children }) => (
  <div className="flex h-screen bg-zinc-950 text-zinc-100">
    <Sidebar />
    <main className="flex-1 overflow-auto">{children}</main>
  </div>
);

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Protected><Shell><Dashboard /></Shell></Protected>} />
        <Route path="/projects" element={<Protected><Shell><Projects /></Shell></Protected>} />
        <Route path="/scans" element={<Protected><Shell><Scans /></Shell></Protected>} />
        <Route path="/scans/:id" element={<Protected><Shell><ScanDetail /></Shell></Protected>} />
        <Route path="/findings" element={<Protected><Shell><Findings /></Shell></Protected>} />
        <Route path="/auth-profiles" element={<Protected><Shell><AuthProfiles /></Shell></Protected>} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Dashboard from './Dashboard.jsx'
import ReportViewer from './ReportViewer.jsx'
import AdminDashboard from './AdminDashboard.jsx'
import DevLab from './DevLab.jsx'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')).render(
  <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
    <Routes>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/report/:id" element={<ReportViewer />} />
      <Route path="/admin" element={<Navigate to="/admin/dashboard" replace />} />
      <Route path="/admin/dashboard" element={<AdminDashboard />} />
      <Route path="/dev" element={<Navigate to="/dev/lab" replace />} />
      <Route path="/dev/lab" element={<DevLab />} />
    </Routes>
  </BrowserRouter>,
)

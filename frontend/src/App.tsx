import { BrowserRouter as Router, Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './components/AuthContext';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import Incidents from './pages/Incidents';
import Assets from './pages/Assets';
import Network from './pages/Network';
import AIDetection from './pages/AI_Detection';
import Simulations from './pages/Simulations';
import Logs from './pages/Logs';
import Reports from './pages/Reports';
import { ForgotPasswordPage, LoginPage, ResetPasswordPage } from './pages/AuthPages';

function ProtectedRoutes() {
  const { email, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="auth-loading" role="status">Checking session...</div>;
  if (!email) return <Navigate to="/login" replace state={{ from: location }} />;
  return <Outlet />;
}

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen bg-gray-50">
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/forgot-password" element={<ForgotPasswordPage />} />
            <Route path="/reset-password" element={<ResetPasswordPage />} />
            <Route path="/" element={<Dashboard />} />
            <Route element={<ProtectedRoutes />}>
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/network" element={<Network />} />
              <Route path="/ai-detection" element={<AIDetection />} />
              <Route path="/simulations" element={<Simulations />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/reports" element={<Reports />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;

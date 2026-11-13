import { useState } from 'react';
import { useLocation } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

const pageTitles: Record<string, string> = {
  '/': 'Command center',
  '/alerts': 'Alert queue',
  '/incidents': 'Incident response',
  '/assets': 'Asset inventory',
  '/network': 'Network architecture',
  '/ai-detection': 'AI detection',
  '/logs': 'Security logs',
  '/reports': 'Incident reports',
  '/simulations': 'Attack lab',
};

const Header = () => {
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { logout } = useAuth();
  const [logoutError, setLogoutError] = useState<string | null>(null);
  const title = pageTitles[pathname] || 'Security operations';

  const signOut = async () => {
    setLogoutError(null);
    try {
      await logout();
      navigate('/login', { replace: true });
    } catch {
      setLogoutError('Could not invalidate the session. Please retry.');
    }
  };

  return (
    <header className="soc-topbar">
      <div>
        <p className="soc-topbar__eyebrow">Industrial Cybersecurity SOC</p>
        <p className="soc-topbar__title">{title}</p>
      </div>
      <span className="soc-topbar__context">Security operations workspace</span>
      {logoutError && <span role="alert" className="soc-topbar__logout-error">{logoutError}</span>}
      <button type="button" className="soc-topbar__logout" onClick={() => void signOut()}>
        Sign out
      </button>
    </header>
  );
};

export default Header;

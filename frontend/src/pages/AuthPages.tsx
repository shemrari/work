import { FormEvent, useState } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../components/AuthContext';
import './Auth.css';

async function responseError(response: Response) {
  const body = await response.json().catch(() => null);
  return typeof body?.detail === 'string' ? body.detail : `Request failed (${response.status})`;
}

function AuthShell({ children, compact = false }: { children: React.ReactNode; compact?: boolean }) {
  return (
    <main className="auth-page">
      <section className={`auth-card${compact ? ' auth-card--compact' : ''}`}>
        <div className="auth-brand">
          <span className="auth-brand__mark" aria-hidden="true">S</span>
          <span>Industrial Cybersecurity SOC</span>
        </div>
        {children}
        <p className="auth-card__footer">Secure operations portal</p>
      </section>
      <p className="auth-page__classification">SECURE OPERATIONS PORTAL</p>
    </main>
  );
}

function PasswordField({
  id,
  label,
  value,
  onChange,
  visible,
  onToggle,
  autoComplete,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  visible: boolean;
  onToggle: () => void;
  autoComplete: string;
}) {
  return (
    <label className="auth-field" htmlFor={id}>
      <span>{label}</span>
      <span className="auth-password-input">
        <input
          id={id}
          name={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          autoComplete={autoComplete}
          required
        />
        <button type="button" className="auth-password-toggle" onClick={onToggle} aria-label={visible ? 'Hide password' : 'Show password'} title={visible ? 'Hide password' : 'Show password'}>
          <span className="auth-eye" aria-hidden="true" />
        </button>
      </span>
    </label>
  );
}

export function LoginPage() {
  const { email, loading, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const destination = (location.state as { from?: { pathname?: string } } | null)?.from?.pathname || '/';

  if (!loading && email) return <Navigate to="/" replace />;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      await login(username, password);
      navigate(destination, { replace: true });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Sign in failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell>
      <div className="auth-heading">
        <p className="auth-eyebrow">SOC ACCESS</p>
        <h1>Industrial Cybersecurity SOC</h1>
        <p className="auth-heading__credit">Developed by Chemrari Maroua</p>
      </div>
      <form className="auth-form" onSubmit={(event) => void submit(event)}>
        <label className="auth-field" htmlFor="username">
          <span>Username</span>
          <input id="username" name="username" type="text" value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="username" required />
        </label>
        <PasswordField id="password" label="Password" value={password} onChange={setPassword} visible={showPassword} onToggle={() => setShowPassword((value) => !value)} autoComplete="current-password" />
        <div className="auth-form__links"><Link to="/forgot-password">Forgot password?</Link></div>
        {error && <p role="alert" className="auth-message auth-message--error">{error}</p>}
        <button className="auth-submit" type="submit" disabled={submitting || loading}>
          {submitting ? 'Signing in...' : 'Sign In'}
        </button>
      </form>
    </AuthShell>
  );
}

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setSubmitting(true);
    setMessage(null);
    setError(null);
    try {
      const response = await fetch('/auth/forgot-password', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      const result = await response.json();
      setMessage(result.message);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Password recovery request failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell compact>
      <div className="auth-heading">
        <p className="auth-eyebrow">ACCOUNT RECOVERY</p>
        <h1>Forgot your password?</h1>
        <p>Enter your email address and we will help you recover your account.</p>
      </div>
      <form className="auth-form" onSubmit={(event) => void submit(event)}>
        <label className="auth-field" htmlFor="recovery-email">
          <span>Email address</span>
          <input id="recovery-email" name="email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" required />
        </label>
        {message && <p role="status" className="auth-message">{message}</p>}
        {error && <p role="alert" className="auth-message auth-message--error">{error}</p>}
        <button className="auth-submit" type="submit" disabled={submitting}>{submitting ? 'Sending...' : 'Send reset link'}</button>
      </form>
      <Link className="auth-back-link" to="/login">Back to login</Link>
    </AuthShell>
  );
}

export function ResetPasswordPage() {
  const location = useLocation();
  const token = new URLSearchParams(location.search).get('token') || '';
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState<string | null>(token ? null : 'Ce lien est invalide ou a expiré. Demandez un nouveau lien.');

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (password.length < 12) {
      setError('Use a password with at least 12 characters.');
      return;
    }
    if (password !== confirmation) {
      setError('The passwords do not match.');
      return;
    }
    setSubmitting(true);
    try {
      const response = await fetch('/auth/reset-password', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, new_password: password }),
      });
      if (!response.ok) throw new Error(await responseError(response));
      setSuccess(true);
      setPassword('');
      setConfirmation('');
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : 'Password reset failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AuthShell compact>
      <div className="auth-heading">
        <p className="auth-eyebrow">SECURE ACCOUNT</p>
        <h1>Reset your password</h1>
        <p>Choose a new password for your SOC account.</p>
      </div>
      {success ? (
        <div className="auth-success-panel">
          <p role="status">Votre mot de passe a été modifié avec succès.</p>
          <Link className="auth-submit auth-submit--link" to="/login">Retour à la connexion</Link>
        </div>
      ) : (
        <form className="auth-form" onSubmit={(event) => void submit(event)}>
          <PasswordField id="new-password" label="New password" value={password} onChange={setPassword} visible={showPassword} onToggle={() => setShowPassword((value) => !value)} autoComplete="new-password" />
          <PasswordField id="confirm-password" label="Confirm new password" value={confirmation} onChange={setConfirmation} visible={showConfirmation} onToggle={() => setShowConfirmation((value) => !value)} autoComplete="new-password" />
          <p className="auth-password-hint">At least 12 characters.</p>
          {error && <p role="alert" className="auth-message auth-message--error">{error}</p>}
          <button className="auth-submit" type="submit" disabled={submitting || !token}>{submitting ? 'Resetting...' : 'Reset password'}</button>
        </form>
      )}
      {!success && <Link className="auth-back-link" to="/login">Back to login</Link>}
    </AuthShell>
  );
}
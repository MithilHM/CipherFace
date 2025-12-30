import React, { useState, useEffect, useRef } from 'react';
import './App.css';
import Button from './components/Button';
import ConsentOnboarding from './ConsentOnboarding';
import ConsentDashboard from './ConsentDashboard';

// SVG Icons as components with enhanced styling
const ShieldIcon = () => (
  <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    <path d="M9 12l2 2 4-4" strokeOpacity="0.7" />
  </svg>
);

const UserIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
    <circle cx="12" cy="7" r="4" />
  </svg>
);

const GridIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
  </svg>
);

const LockIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
    <circle cx="12" cy="16" r="1" />
  </svg>
);

const SettingsIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);

const LogoutIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <polyline points="16 17 21 12 16 7" />
    <line x1="21" y1="12" x2="9" y2="12" />
  </svg>
);

const ScanIcon = () => (
  <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 7V5a2 2 0 0 1 2-2h2" />
    <path d="M17 3h2a2 2 0 0 1 2 2v2" />
    <path d="M21 17v2a2 2 0 0 1-2 2h-2" />
    <path d="M7 21H5a2 2 0 0 1-2-2v-2" />
    <line x1="7" y1="12" x2="17" y2="12" />
  </svg>
);

const App = () => {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isScanning, setIsScanning] = useState(false);
  const [status, setStatus] = useState('idle');
  const [message, setMessage] = useState('');
  const [needsConsent, setNeedsConsent] = useState(false);
  const [hasConsent, setHasConsent] = useState(false);

  const videoRef = useRef(null);
  const canvasRef = useRef(null);

  useEffect(() => {
    if (token) {
      checkUserAndConsent();
    }
  }, [token]);

  const checkUserAndConsent = async () => {
    try {
      const storedUser = localStorage.getItem('user');
      if (storedUser) {
        const userData = JSON.parse(storedUser);
        setUser(userData);

        const consentCheck = await fetch(`/api/consent/verify/${userData.id}/AUTHENTICATION`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (consentCheck.ok) {
          const consentData = await consentCheck.json();
          setHasConsent(consentData.valid);
          setNeedsConsent(!consentData.valid);
        } else {
          setNeedsConsent(true);
        }
      }
    } catch (err) {
      console.error('Failed to check consent:', err);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const username = e.target.username.value;
    try {
      const resp = await fetch('/api/auth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
      });

      if (!resp.ok) throw new Error('Login failed');

      const data = await resp.json();
      if (data.access_token) {
        setToken(data.access_token);
        localStorage.setItem('token', data.access_token);
        localStorage.setItem('user', JSON.stringify({
          username: data.username,
          id: data.user_id
        }));
        setUser({ username: data.username, id: data.user_id });
        setNeedsConsent(true);
      }
    } catch (err) {
      alert('Login failed: ' + err.message);
    }
  };

  const handleConsentComplete = () => {
    setNeedsConsent(false);
    setHasConsent(true);
  };

  const startScanner = async () => {
    setIsScanning(true);
    setStatus('capturing');
    setMessage('');
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          facingMode: 'user',
          width: { ideal: 640 },
          height: { ideal: 480 }
        }
      });
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
    } catch (err) {
      setMessage('Camera access denied: ' + err.message);
      setStatus('error');
      setIsScanning(false);
    }
  };

  const stopScanner = () => {
    if (videoRef.current && videoRef.current.srcObject) {
      videoRef.current.srcObject.getTracks().forEach(track => track.stop());
    }
    setIsScanning(false);
    setStatus('idle');
    setMessage('');
  };

  const captureAndProcess = async () => {
    setStatus('processing');
    setMessage('Encrypting biometric data...');

    const canvas = canvasRef.current;
    const video = videoRef.current;

    if (!canvas || !video) {
      setStatus('error');
      setMessage('Camera not ready');
      return;
    }

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(video, 0, 0);

    const imageData = canvas.toDataURL('image/jpeg', 0.8).split(',')[1];

    try {
      const endpoint = activeTab === 'enroll' ? '/api/register' : '/api/verify';
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ image: imageData })
      });

      const result = await resp.json();

      if (resp.ok) {
        setStatus('success');
        if (activeTab === 'enroll') {
          setMessage(`✓ Identity Secured! Template ID: ${result.template_id}`);
        } else {
          setMessage(`✓ Match Confidence: ${(result.confidence * 100).toFixed(1)}%`);
        }

        setTimeout(() => {
          stopScanner();
          setActiveTab('dashboard');
        }, 3000);
      } else {
        throw new Error(result.error || result.message || 'Operation failed');
      }
    } catch (err) {
      setStatus('error');
      setMessage('Error: ' + err.message);
    }
  };

  // Login Screen
  if (!token) {
    return (
      <div className="login-screen">
        <div className="login-card glass">
          <div className="logo"><ShieldIcon /> FHE.Face</div>
          <h3>Secure Gateway</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', textAlign: 'center', lineHeight: 1.6 }}>
            Privacy-Preserving Biometric Authentication<br />
            <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Powered by Homomorphic Encryption</span>
          </p>
          <form className="nav-links" onSubmit={handleLogin} style={{ gap: '1.25rem' }}>
            <div className="form-group">
              <label>Identity Handle</label>
              <input
                name="username"
                placeholder="Enter your username"
                required
                autoComplete="username"
                autoFocus
              />
            </div>
            <Button type="submit" size="lg" style={{ width: '100%' }}>
              Initialize Secure Session
            </Button>
          </form>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)', textAlign: 'center', marginTop: '0.5rem' }}>
            🔐 128-bit FHE • CKKS Encryption • GDPR Compliant
          </p>
        </div>
      </div>
    );
  }

  // Consent Onboarding
  if (needsConsent && user?.id) {
    return <ConsentOnboarding userId={user.id} onComplete={handleConsentComplete} />;
  }

  // Main Dashboard
  return (
    <div className="app-container">
      <aside className="sidebar">
        <div className="logo"><ShieldIcon /> FHE.Face</div>
        <nav className="nav-links">
          <div
            className={`nav-item ${activeTab === 'dashboard' ? 'active' : ''}`}
            onClick={() => { stopScanner(); setActiveTab('dashboard'); }}
          >
            <GridIcon /> Dashboard
          </div>
          <div
            className={`nav-item ${activeTab === 'enroll' ? 'active' : ''}`}
            onClick={() => { stopScanner(); setActiveTab('enroll'); }}
          >
            <UserIcon /> Enroll Identity
          </div>
          <div
            className={`nav-item ${activeTab === 'verify' ? 'active' : ''}`}
            onClick={() => { stopScanner(); setActiveTab('verify'); }}
          >
            <LockIcon /> Secure Auth
          </div>
          <div
            className={`nav-item ${activeTab === 'privacy' ? 'active' : ''}`}
            onClick={() => { stopScanner(); setActiveTab('privacy'); }}
          >
            <SettingsIcon /> Privacy Center
          </div>
        </nav>
        <div style={{ marginTop: 'auto' }}>
          <div
            className="nav-item"
            onClick={() => { localStorage.clear(); window.location.reload(); }}
            style={{ color: 'var(--text-dim)' }}
          >
            <LogoutIcon /> Sign Out
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="dashboard-header">
          <div>
            <h1>Shield Portal</h1>
            <p style={{ color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              Welcome back, <span className="mono" style={{ color: 'var(--primary-light)' }}>{user?.username}</span>
            </p>
          </div>
          <div className="status-badge status-secure">
            {hasConsent ? 'FHE Active' : 'Consent Required'}
          </div>
        </header>

        {/* Dashboard View */}
        {activeTab === 'dashboard' && (
          <div className="portal-view">
            <div className="stats-grid">
              <div className="stat-card glass">
                <div className="stat-header">
                  Identity Protection
                  <span>FHE-CKKS</span>
                </div>
                <div className="stat-value">128-bit</div>
                <div className="stat-footer">Quantum Resistant Standard</div>
              </div>
              <div className="stat-card glass">
                <div className="stat-header">
                  Consent Status
                  <span>DPDP</span>
                </div>
                <div className="stat-value">{hasConsent ? 'Active' : 'Pending'}</div>
                <div className="stat-footer">{hasConsent ? 'All requirements met' : 'Consent required'}</div>
              </div>
              <div className="stat-card glass">
                <div className="stat-header">
                  Polynomial Degree
                  <span>CKKS</span>
                </div>
                <div className="stat-value">8192</div>
                <div className="stat-footer">Ring Dimension</div>
              </div>
            </div>

            <div className="glass" style={{ width: '100%', padding: '2rem' }}>
              <h3 style={{ marginBottom: '0.5rem' }}>Quick Actions</h3>
              <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem', fontSize: '0.875rem' }}>
                Manage your biometric identity with military-grade encryption
              </p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                <Button onClick={() => setActiveTab('enroll')}>
                  👤 Enroll New Template
                </Button>
                <Button variant="ghost" onClick={() => setActiveTab('verify')}>
                  🔓 Authenticate
                </Button>
                <Button variant="ghost" onClick={() => setActiveTab('privacy')}>
                  ⚙️ Privacy Settings
                </Button>
              </div>
            </div>

            {/* Security Features */}
            <div className="glass" style={{ width: '100%', padding: '2rem' }}>
              <h3 style={{ marginBottom: '1.5rem' }}>Security Features</h3>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem' }}>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <div style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '12px',
                    background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(124, 58, 237, 0.1) 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0
                  }}>
                    🔐
                  </div>
                  <div>
                    <h4 style={{ marginBottom: '0.25rem' }}>Homomorphic Encryption</h4>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                      Computations on encrypted data without decryption
                    </p>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <div style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '12px',
                    background: 'linear-gradient(135deg, rgba(6, 214, 160, 0.2) 0%, rgba(6, 214, 160, 0.1) 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0
                  }}>
                    🛡️
                  </div>
                  <div>
                    <h4 style={{ marginBottom: '0.25rem' }}>Zero-Knowledge Matching</h4>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                      Your face is never seen during authentication
                    </p>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
                  <div style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '12px',
                    background: 'linear-gradient(135deg, rgba(244, 114, 182, 0.2) 0%, rgba(244, 114, 182, 0.1) 100%)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0
                  }}>
                    📋
                  </div>
                  <div>
                    <h4 style={{ marginBottom: '0.25rem' }}>GDPR & DPDP Compliant</h4>
                    <p style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
                      Full consent management and data portability
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Enroll / Verify Views */}
        {(activeTab === 'enroll' || activeTab === 'verify') && (
          <div className="portal-view">
            <div style={{ textAlign: 'center', maxWidth: '600px' }}>
              <h2>{activeTab === 'enroll' ? '🆔 Biometric Enrollment' : '🔐 Identity Verification'}</h2>
              <p style={{ color: 'var(--text-muted)', marginTop: '0.75rem', lineHeight: 1.6 }}>
                {activeTab === 'enroll'
                  ? 'Create a secure encrypted template of your biometric identity'
                  : 'Authenticate using your encrypted biometric profile'
                }
              </p>
            </div>

            {!isScanning ? (
              <div className="glass" style={{
                padding: '4rem 3rem',
                textAlign: 'center',
                width: '100%',
                maxWidth: '600px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '1.5rem'
              }}>
                <div style={{
                  width: '80px',
                  height: '80px',
                  borderRadius: '50%',
                  background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(6, 214, 160, 0.1) 100%)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: '0.5rem'
                }}>
                  <ScanIcon />
                </div>
                <div>
                  <h3 style={{ marginBottom: '0.5rem' }}>Ready to Scan</h3>
                  <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                    Position your face in the frame for secure capture
                  </p>
                </div>
                <Button onClick={startScanner} size="lg">
                  Activate Bio-Scanner
                </Button>
              </div>
            ) : (
              <>
                <div className="scanner-container">
                  <video ref={videoRef} autoPlay playsInline muted className="video-feed" />
                  <div className="scan-overlay">
                    <div className="scan-line" />
                    <div className="face-portal" />
                  </div>
                  {/* Bottom corner markers */}
                  <div style={{
                    position: 'absolute',
                    bottom: '20px',
                    left: '20px',
                    width: '40px',
                    height: '40px',
                    border: '3px solid var(--accent)',
                    borderTop: 'none',
                    borderRight: 'none',
                    borderRadius: '4px'
                  }} />
                  <div style={{
                    position: 'absolute',
                    bottom: '20px',
                    right: '20px',
                    width: '40px',
                    height: '40px',
                    border: '3px solid var(--accent)',
                    borderTop: 'none',
                    borderLeft: 'none',
                    borderRadius: '4px'
                  }} />
                </div>

                <div style={{ marginTop: '1.5rem', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                  {status === 'capturing' && (
                    <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
                      <Button onClick={captureAndProcess}>
                        ⚡ Capture & Encrypt
                      </Button>
                      <Button variant="ghost" onClick={stopScanner}>
                        Cancel
                      </Button>
                    </div>
                  )}
                  {status === 'processing' && (
                    <Button variant="glass" loading disabled style={{ minWidth: '200px' }}>
                      <span className="mono">{message}</span>
                    </Button>
                  )}
                  {status === 'success' && (
                    <div style={{
                      color: 'var(--accent)',
                      fontWeight: 600,
                      fontSize: '1.125rem',
                      padding: '1rem 2rem',
                      background: 'rgba(6, 214, 160, 0.1)',
                      borderRadius: '12px',
                      border: '1px solid rgba(6, 214, 160, 0.2)'
                    }}>
                      {message}
                    </div>
                  )}
                  {status === 'error' && (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '1rem' }}>
                      <div style={{
                        color: 'var(--error)',
                        fontWeight: 600,
                        padding: '1rem 2rem',
                        background: 'rgba(239, 68, 68, 0.1)',
                        borderRadius: '12px',
                        border: '1px solid rgba(239, 68, 68, 0.2)'
                      }}>
                        {message}
                      </div>
                      <Button variant="ghost" onClick={stopScanner}>Close Scanner</Button>
                    </div>
                  )}
                </div>
              </>
            )}
            <canvas ref={canvasRef} style={{ display: 'none' }} />
          </div>
        )}

        {/* Privacy Center */}
        {activeTab === 'privacy' && (
          <ConsentDashboard userId={user?.id} token={token} />
        )}
      </main>
    </div>
  );
};

export default App;

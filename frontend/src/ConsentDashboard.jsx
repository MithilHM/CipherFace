import React, { useState, useEffect } from 'react';
import Button from './components/Button';

const ConsentDashboard = ({ userId, token }) => {
  const [activeTab, setActiveTab] = useState('consents');
  const [consents, setConsents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showRevokeModal, setShowRevokeModal] = useState(null);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  useEffect(() => {
    fetchDashboardData();
  }, [userId]);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const response = await fetch(`/api/consent/dashboard/${userId}`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (!response.ok) {
        if (response.status === 401) {
          localStorage.clear();
          window.location.reload();
          return;
        }
        throw new Error('Failed to fetch dashboard data');
      }

      const data = await response.json();

      const mappedConsents = (data.active_consents || []).map(c => ({
        id: c.consent_id,
        purpose: c.purpose,
        granted_at: c.granted_at,
        expires_at: c.expires_at,
        is_active: c.is_valid,
        remaining_days: c.remaining_days
      }));

      const mappedAuditLogs = (data.authentication_history || []).map(log => ({
        action: log.action,
        timestamp: log.timestamp,
        success: log.result === 'success',
        metadata: {
          ip_address: log.location || 'Unknown',
          device: log.device || 'Unknown'
        }
      }));

      setConsents(mappedConsents);
      setAuditLogs(mappedAuditLogs);
    } catch (err) {
      console.error('Dashboard fetch error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeConsent = async () => {
    try {
      setActionLoading(true);
      const response = await fetch('/api/consent/revoke', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          consent_id: showRevokeModal.id,
          revocation_reason: 'User requested revocation'
        })
      });

      if (!response.ok) throw new Error('Failed to revoke consent');

      setShowRevokeModal(null);
      fetchDashboardData();
    } catch (err) {
      alert('Failed to revoke consent: ' + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleExportData = async () => {
    try {
      setActionLoading(true);
      const response = await fetch('/api/consent/export-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ confirm: true })
      });

      if (!response.ok) throw new Error('Export failed');

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `fhe-face-data-export-${Date.now()}.json`;
      a.click();
    } catch (err) {
      alert('Export failed: ' + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const handleDeleteBiometricData = async () => {
    try {
      setActionLoading(true);
      const response = await fetch('/api/consent/delete-biometric-data', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ confirmation: 'DELETE_MY_DATA' })
      });

      if (!response.ok) throw new Error('Deletion failed');

      alert('Your biometric data has been permanently deleted.');
      setShowDeleteModal(false);
      localStorage.clear();
      window.location.reload();
    } catch (err) {
      alert('Deletion failed: ' + err.message);
    } finally {
      setActionLoading(false);
    }
  };

  const getDaysRemaining = (expiresAt) => {
    const days = Math.floor((new Date(expiresAt) - new Date()) / (1000 * 60 * 60 * 24));
    return days;
  };

  const getStatusColor = (daysRemaining) => {
    if (daysRemaining > 30) return { bg: 'rgba(6, 214, 160, 0.1)', border: 'rgba(6, 214, 160, 0.2)', text: 'var(--accent)' };
    if (daysRemaining > 7) return { bg: 'rgba(245, 158, 11, 0.1)', border: 'rgba(245, 158, 11, 0.2)', text: '#f59e0b' };
    return { bg: 'rgba(239, 68, 68, 0.1)', border: 'rgba(239, 68, 68, 0.2)', text: 'var(--error)' };
  };

  const tabs = [
    { id: 'consents', label: 'Active Consents', icon: '✓' },
    { id: 'history', label: 'Auth History', icon: '📜' },
    { id: 'data', label: 'Data Management', icon: '🗄️' }
  ];

  if (loading) {
    return (
      <div style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '4rem',
        gap: '1rem'
      }}>
        <div style={{
          width: '48px',
          height: '48px',
          border: '3px solid var(--glass-border)',
          borderTopColor: 'var(--primary)',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }} />
        <div className="mono" style={{ color: 'var(--text-muted)' }}>LOADING_DASHBOARD...</div>
        <style>{`
          @keyframes spin {
            to { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    );
  }

  return (
    <div className="portal-view" style={{ alignItems: 'stretch' }}>
      <div style={{ textAlign: 'center', marginBottom: '1rem' }}>
        <h2>🛡️ Privacy & Consent Center</h2>
        <p style={{ color: 'var(--text-muted)', marginTop: '0.5rem' }}>
          Manage your data, consents, and privacy settings
        </p>
      </div>

      {/* Tab Navigation */}
      <div style={{
        display: 'flex',
        gap: '0.5rem',
        padding: '0.5rem',
        background: 'var(--surface)',
        borderRadius: '16px',
        marginBottom: '1.5rem'
      }}>
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              flex: 1,
              padding: '0.875rem 1.25rem',
              border: 'none',
              borderRadius: '12px',
              background: activeTab === tab.id
                ? 'linear-gradient(135deg, var(--primary) 0%, #5b21b6 100%)'
                : 'transparent',
              color: activeTab === tab.id ? 'white' : 'var(--text-muted)',
              cursor: 'pointer',
              transition: 'all 0.3s ease',
              fontWeight: 600,
              fontSize: '0.875rem',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              boxShadow: activeTab === tab.id ? '0 4px 20px rgba(124, 58, 237, 0.3)' : 'none'
            }}
          >
            <span>{tab.icon}</span>
            <span style={{ display: window.innerWidth > 600 ? 'inline' : 'none' }}>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Active Consents Tab */}
      {activeTab === 'consents' && (
        <div className="glass" style={{ padding: '1.75rem' }}>
          <h3 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem' }}>✓</span> Active Consent Records
          </h3>
          {consents.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '3rem',
              color: 'var(--text-muted)'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}>📋</div>
              <p>No active consents found</p>
              <p style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}>Grant consent to enable biometric features</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {consents.map(consent => {
                const daysRemaining = getDaysRemaining(consent.expires_at);
                const colors = getStatusColor(daysRemaining);
                return (
                  <div
                    key={consent.id}
                    style={{
                      padding: '1.25rem 1.5rem',
                      background: colors.bg,
                      borderRadius: '14px',
                      border: `1px solid ${colors.border}`,
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '1rem',
                      transition: 'all 0.3s ease'
                    }}
                  >
                    <div style={{ flex: 1, minWidth: '200px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
                        <strong style={{ fontSize: '1rem' }}>{consent.purpose}</strong>
                        <span style={{
                          padding: '0.25rem 0.75rem',
                          borderRadius: '20px',
                          fontSize: '0.6875rem',
                          fontWeight: 600,
                          textTransform: 'uppercase',
                          background: consent.is_active ? 'rgba(6, 214, 160, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          color: consent.is_active ? 'var(--accent)' : 'var(--error)',
                          border: `1px solid ${consent.is_active ? 'rgba(6, 214, 160, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`
                        }}>
                          {consent.is_active ? 'Active' : 'Revoked'}
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: '1.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                        <span>Granted: {new Date(consent.granted_at).toLocaleDateString()}</span>
                        <span style={{ color: colors.text }}>
                          {daysRemaining > 0 ? `${daysRemaining} days remaining` : 'Expired'}
                        </span>
                      </div>
                    </div>
                    {consent.is_active && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setShowRevokeModal(consent)}
                        style={{ borderColor: 'rgba(239, 68, 68, 0.3)', color: 'var(--error)' }}
                      >
                        Revoke
                      </Button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Authentication History Tab */}
      {activeTab === 'history' && (
        <div className="glass" style={{ padding: '1.75rem' }}>
          <h3 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem' }}>📜</span> Authentication History
          </h3>
          {auditLogs.length === 0 ? (
            <div style={{
              textAlign: 'center',
              padding: '3rem',
              color: 'var(--text-muted)'
            }}>
              <div style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.5 }}>🔍</div>
              <p>No authentication history available</p>
              <p style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}>Your authentication events will appear here</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {auditLogs.slice(0, 10).map((log, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '1.25rem',
                    background: 'var(--surface)',
                    borderRadius: '12px',
                    borderLeft: `4px solid ${log.success ? 'var(--accent)' : 'var(--error)'}`,
                    transition: 'all 0.3s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <div>
                      <strong className="mono" style={{ fontSize: '0.9375rem' }}>{log.action}</strong>
                      <div style={{ fontSize: '0.8125rem', color: 'var(--text-muted)', marginTop: '0.375rem' }}>
                        {new Date(log.timestamp).toLocaleString()}
                      </div>
                      {log.metadata && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginTop: '0.375rem' }}>
                          {log.metadata.ip_address && `IP: ${log.metadata.ip_address}`}
                        </div>
                      )}
                    </div>
                    <span style={{
                      padding: '0.375rem 0.875rem',
                      borderRadius: '20px',
                      background: log.success ? 'rgba(6, 214, 160, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                      color: log.success ? 'var(--accent)' : 'var(--error)',
                      fontSize: '0.6875rem',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em'
                    }}>
                      {log.success ? '✓ Success' : '✕ Failed'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Data Management Tab */}
      {activeTab === 'data' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          {/* Export Data */}
          <div className="glass" style={{ padding: '1.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.25rem' }}>
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '14px',
                background: 'linear-gradient(135deg, rgba(124, 58, 237, 0.2) 0%, rgba(124, 58, 237, 0.1) 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem',
                flexShrink: 0
              }}>
                📥
              </div>
              <div style={{ flex: 1 }}>
                <h3 style={{ marginBottom: '0.5rem' }}>Export Your Data</h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.25rem', fontSize: '0.9375rem', lineHeight: 1.6 }}>
                  Download all your consent records and authentication history as a portable JSON file
                </p>
                <Button onClick={handleExportData} loading={actionLoading}>
                  📥 Download Data Package
                </Button>
              </div>
            </div>
          </div>

          {/* Data Retention Policy */}
          <div className="glass" style={{ padding: '1.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.25rem' }}>
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '14px',
                background: 'linear-gradient(135deg, rgba(6, 214, 160, 0.2) 0%, rgba(6, 214, 160, 0.1) 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem',
                flexShrink: 0
              }}>
                📋
              </div>
              <div style={{ flex: 1 }}>
                <h3 style={{ marginBottom: '1rem' }}>Data Retention Policy</h3>
                <ul style={{
                  color: 'var(--text-muted)',
                  lineHeight: 2,
                  paddingLeft: '1.25rem',
                  fontSize: '0.9375rem'
                }}>
                  <li>Biometric templates stored as <strong style={{ color: 'var(--text-secondary)' }}>encrypted CKKS ciphertexts</strong></li>
                  <li>Templates auto-deleted <strong style={{ color: 'var(--text-secondary)' }}>90 days</strong> after consent expiration</li>
                  <li>Audit logs retained for <strong style={{ color: 'var(--text-secondary)' }}>1 year</strong> for security</li>
                  <li>Request <strong style={{ color: 'var(--text-secondary)' }}>immediate deletion</strong> at any time</li>
                  <li>Compliant with <strong style={{ color: 'var(--accent)' }}>GDPR</strong> & <strong style={{ color: 'var(--accent)' }}>DPDP Act 2023</strong></li>
                </ul>
              </div>
            </div>
          </div>

          {/* Danger Zone */}
          <div className="glass" style={{
            padding: '1.75rem',
            borderColor: 'rgba(239, 68, 68, 0.3)',
            background: 'rgba(239, 68, 68, 0.02)'
          }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: '1.25rem' }}>
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '14px',
                background: 'linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(239, 68, 68, 0.1) 100%)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem',
                flexShrink: 0
              }}>
                ⚠️
              </div>
              <div style={{ flex: 1 }}>
                <h3 style={{ marginBottom: '0.5rem', color: 'var(--error)' }}>Danger Zone</h3>
                <p style={{ color: 'var(--text-muted)', marginBottom: '1.25rem', fontSize: '0.9375rem', lineHeight: 1.6 }}>
                  Permanently delete all your biometric data and consent records. This action cannot be reversed.
                </p>
                <Button
                  variant="danger"
                  onClick={() => setShowDeleteModal(true)}
                >
                  🗑️ Delete All My Data
                </Button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Revoke Confirmation Modal */}
      {showRevokeModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          background: 'rgba(0, 0, 0, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.5rem',
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <div className="glass" style={{
            maxWidth: '450px',
            width: '100%',
            padding: '2rem',
            animation: 'scaleIn 0.3s ease-out'
          }}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'rgba(245, 158, 11, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem',
                fontSize: '1.75rem'
              }}>
                ⚠️
              </div>
              <h3 style={{ marginBottom: '0.75rem' }}>Revoke Consent?</h3>
              <p style={{ color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Are you sure you want to revoke consent for <strong style={{ color: 'var(--text-main)' }}>{showRevokeModal.purpose}</strong>?
                This will prevent authentication until you grant consent again.
              </p>
            </div>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
              <Button variant="ghost" onClick={() => setShowRevokeModal(null)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={handleRevokeConsent}
                loading={actionLoading}
              >
                Yes, Revoke
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          width: '100%',
          height: '100%',
          background: 'rgba(0, 0, 0, 0.85)',
          backdropFilter: 'blur(8px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.5rem',
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <div className="glass" style={{
            maxWidth: '500px',
            width: '100%',
            padding: '2rem',
            borderColor: 'rgba(239, 68, 68, 0.3)',
            animation: 'scaleIn 0.3s ease-out'
          }}>
            <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
              <div style={{
                width: '64px',
                height: '64px',
                borderRadius: '50%',
                background: 'rgba(239, 68, 68, 0.15)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 1rem',
                fontSize: '1.75rem'
              }}>
                🗑️
              </div>
              <h3 style={{ marginBottom: '0.75rem', color: 'var(--error)' }}>Permanently Delete Data?</h3>
            </div>
            <div style={{
              background: 'rgba(239, 68, 68, 0.1)',
              borderRadius: '12px',
              padding: '1.25rem',
              marginBottom: '1.5rem'
            }}>
              <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem', fontWeight: 500 }}>
                This will permanently delete:
              </p>
              <ul style={{ color: 'var(--text-muted)', lineHeight: 1.8, paddingLeft: '1.25rem', fontSize: '0.9375rem' }}>
                <li>All encrypted biometric templates</li>
                <li>All consent records</li>
                <li>Authentication history (audit logs kept 30 days)</li>
              </ul>
            </div>
            <p style={{
              color: 'var(--error)',
              textAlign: 'center',
              marginBottom: '1.5rem',
              fontWeight: 600,
              fontSize: '0.9375rem'
            }}>
              ⚠️ This action cannot be undone. You will be logged out immediately.
            </p>
            <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center' }}>
              <Button variant="ghost" onClick={() => setShowDeleteModal(false)}>
                Cancel
              </Button>
              <Button
                variant="danger"
                onClick={handleDeleteBiometricData}
                loading={actionLoading}
              >
                Delete Everything
              </Button>
            </div>
          </div>
        </div>
      )}

      <style>{`
        @keyframes fadeIn {
          from { opacity: 0; }
          to { opacity: 1; }
        }
        @keyframes scaleIn {
          from { opacity: 0; transform: scale(0.95); }
          to { opacity: 1; transform: scale(1); }
        }
      `}</style>
    </div>
  );
};

export default ConsentDashboard;

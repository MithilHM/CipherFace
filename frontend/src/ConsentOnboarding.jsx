import React, { useState } from 'react';
import Button from './components/Button';

const ConsentOnboarding = ({ userId, onComplete }) => {
  const [step, setStep] = useState(0);
  const [consents, setConsents] = useState({
    authentication: false,
    dataProcessing: false,
    analytics: false
  });
  const [isLoading, setIsLoading] = useState(false);

  const steps = [
    {
      title: 'Welcome to FHE.Face',
      description: 'Next-generation biometric authentication powered by fully homomorphic encryption. Your privacy is mathematically guaranteed.',
      icon: '🔐',
      colorClass: 'bg-gradient-to-br from-primary to-purple-400'
    },
    {
      title: 'How It Works',
      description: 'Your face is converted to an encrypted mathematical representation using CKKS homomorphic encryption. All matching computations happen entirely in encrypted space — we never see your actual biometric data.',
      icon: '🧮',
      colorClass: 'bg-gradient-to-br from-accent to-emerald-400'
    },
    {
      title: 'Your Consent Matters',
      description: 'We require your explicit permission to process biometric data. You maintain full control and can revoke access or delete your data at any time.',
      icon: '✓',
      colorClass: 'bg-gradient-to-br from-pink-400 to-pink-600'
    }
  ];

  const handleGrantConsent = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem('token');

      if (!token) {
        throw new Error('Authentication token not found. Please log in again.');
      }
      if (!userId) {
        throw new Error('User ID not found. Please log in again.');
      }

      console.log('Granting consent for user:', userId);

      const authResponse = await fetch('/api/consent/grant', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          user_id: userId,
          purpose: 'AUTHENTICATION',
          consent_text: 'I consent to the processing of my biometric data for authentication purposes using homomorphic encryption.',
          expires_in_days: 365
        })
      });

      if (!authResponse.ok) {
        const errorData = await authResponse.json().catch(() => ({}));
        const errorMsg = errorData.error || errorData.message || `Server error: ${authResponse.status}`;

        if (authResponse.status === 401 || errorMsg.toLowerCase().includes('token')) {
          console.error('JWT token invalid - clearing session');
          localStorage.removeItem('token');
          localStorage.removeItem('user');
          alert('Session expired. Please log in again.');
          window.location.reload();
          return;
        }

        throw new Error(errorMsg);
      }

      onComplete();
    } catch (err) {
      console.error('Consent grant error:', err);
      alert('Failed to grant consent: ' + err.message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 w-full h-full bg-bg-deep flex items-center justify-center p-6 z-50">
      {/* Animated background orbs */}
      <div className="absolute top-[10%] left-[10%] w-[400px] h-[400px] bg-primary/10 rounded-full blur-[60px] animate-float pointer-events-none" />
      <div className="absolute bottom-[10%] right-[10%] w-[300px] h-[300px] bg-accent/10 rounded-full blur-[50px] animate-float-reverse pointer-events-none" />

      {/* Glass Card */}
      <div className="relative w-full max-w-xl bg-white/5 backdrop-blur-xl border border-white/10 rounded-3xl p-8 md:p-12 text-center shadow-2xl animate-scale-in">
        {/* Helper for Skip functionality */}
        {step === 0 && (
          <div className="absolute top-6 right-6">
            <button
              onClick={() => setStep(2)}
              className="text-sm text-text-dim hover:text-text-secondary transition-colors"
            >
              Skip
            </button>
          </div>
        )}

        {/* Icon */}
        <div className={`w-24 h-24 rounded-full ${steps[step].colorClass} flex items-center justify-center mx-auto mb-8 text-4xl shadow-lg ring-1 ring-white/20 animate-pulse-slow`}>
          {steps[step].icon}
        </div>

        {/* Title */}
        <h2 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-text-main to-text-secondary mb-4">
          {steps[step].title}
        </h2>

        {/* Description */}
        <p className="text-text-muted text-lg leading-relaxed mb-10">
          {steps[step].description}
        </p>

        {/* Consent Form (Step 3) */}
        {step === 2 && (
          <div className="bg-white/5 border border-white/5 rounded-2xl p-6 mb-8 text-left">
            <h4 className="text-text-main font-semibold mb-6">Required Permissions</h4>

            <label className={`flex items-start gap-4 p-4 rounded-xl cursor-pointer transition-all duration-200 border ${consents.authentication ? 'bg-primary/10 border-primary/20' : 'bg-transparent border-transparent hover:bg-white/5'}`}>
              <input
                type="checkbox"
                checked={consents.authentication}
                onChange={(e) => setConsents({ ...consents, authentication: e.target.checked })}
                className="mt-1 w-5 h-5 rounded border-white/20 bg-white/5 text-primary focus:ring-primary focus:ring-offset-0"
              />
              <div>
                <strong className="block text-text-main font-medium mb-1">
                  Biometric Authentication
                </strong>
                <small className="block text-text-muted leading-snug">
                  Process encrypted face embeddings for secure passwordless login
                </small>
              </div>
            </label>

            <label className={`flex items-start gap-4 p-4 rounded-xl cursor-pointer transition-all duration-200 border mt-3 ${consents.dataProcessing ? 'bg-primary/10 border-primary/20' : 'bg-transparent border-transparent hover:bg-white/5'}`}>
              <input
                type="checkbox"
                checked={consents.dataProcessing}
                onChange={(e) => setConsents({ ...consents, dataProcessing: e.target.checked })}
                className="mt-1 w-5 h-5 rounded border-white/20 bg-white/5 text-primary focus:ring-primary focus:ring-offset-0"
              />
              <div>
                <strong className="block text-text-main font-medium mb-1">
                  Encrypted Data Storage
                </strong>
                <small className="block text-text-muted leading-snug">
                  Store encrypted biometric templates in our zero-knowledge database
                </small>
              </div>
            </label>

            {/* Security Note */}
            <div className="mt-6 p-4 rounded-xl bg-gradient-to-br from-primary/10 to-accent/5 border border-primary/10">
              <div className="space-y-2">
                <div className="flex items-center gap-3 text-sm text-text-secondary">
                  <span className="text-accent">✓</span>
                  128-bit Fully Homomorphic Encryption (CKKS)
                </div>
                <div className="flex items-center gap-3 text-sm text-text-secondary">
                  <span className="text-accent">✓</span>
                  Revoke consent and delete data anytime
                </div>
                <div className="flex items-center gap-3 text-sm text-text-secondary">
                  <span className="text-accent">✓</span>
                  GDPR & India's DPDP Act 2023 compliant
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Navigation & Actions */}
        <div className="flex items-center justify-center gap-4">
          {step > 0 && (
            <Button variant="ghost" onClick={() => setStep(step - 1)}>
              ← Back
            </Button>
          )}

          {step < 2 ? (
            <Button onClick={() => setStep(step + 1)}>
              Continue →
            </Button>
          ) : (
            <Button
              onClick={handleGrantConsent}
              disabled={!consents.authentication || !consents.dataProcessing}
              loading={isLoading}
            >
              Grant Consent & Continue
            </Button>
          )}
        </div>

        {/* Step Indicators */}
        <div className="flex gap-2 justify-center mt-10">
          {steps.map((_, i) => (
            <button
              key={i}
              onClick={() => setStep(i)}
              aria-label={`Go to step ${i + 1}`}
              className={`h-2 rounded-full transition-all duration-300 ${i === step
                  ? 'w-6 bg-primary shadow-[0_0_12px_var(--primary-glow)]'
                  : 'w-2 bg-white/20 hover:bg-white/30'
                }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
};

export default ConsentOnboarding;

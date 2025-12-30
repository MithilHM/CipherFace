import React from 'react';

const Button = ({
  children,
  variant = 'primary',
  className = '',
  disabled = false,
  type = 'button',
  size = 'default',
  loading = false,
  icon,
  style,
  ...props
}) => {
  // Base styles
  const baseStyles = {
    display: 'inline-flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '0.625rem',
    fontWeight: 600,
    fontFamily: 'inherit',
    borderRadius: '12px',
    border: 'none',
    cursor: disabled ? 'not-allowed' : loading ? 'wait' : 'pointer',
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
    position: 'relative',
    overflow: 'hidden',
    outline: 'none',
    textDecoration: 'none',
    opacity: disabled ? 0.5 : 1,
    transform: 'translateY(0)',
  };

  // Size variations
  const sizeStyles = {
    sm: {
      padding: '0.5rem 1rem',
      fontSize: '0.875rem',
    },
    default: {
      padding: '0.75rem 1.5rem',
      fontSize: '0.9375rem',
    },
    lg: {
      padding: '1rem 2rem',
      fontSize: '1rem',
    },
  };

  // Variant styles
  const variantStyles = {
    primary: {
      background: 'linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(124, 58, 237, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.15)',
    },
    secondary: {
      background: 'linear-gradient(135deg, #06d6a0 0%, #059669 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(6, 214, 160, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.15)',
    },
    ghost: {
      background: 'rgba(255, 255, 255, 0.03)',
      color: 'var(--text-main, #e2e8f0)',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.05)',
    },
    danger: {
      background: 'linear-gradient(135deg, #ef4444 0%, #b91c1c 100%)',
      color: '#ffffff',
      boxShadow: '0 4px 20px rgba(239, 68, 68, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.15)',
    },
    glass: {
      background: 'rgba(255, 255, 255, 0.05)',
      backdropFilter: 'blur(20px)',
      WebkitBackdropFilter: 'blur(20px)',
      color: 'var(--text-main, #e2e8f0)',
      border: '1px solid rgba(255, 255, 255, 0.1)',
      boxShadow: '0 4px 30px rgba(0, 0, 0, 0.2), inset 0 1px 0 rgba(255, 255, 255, 0.05)',
    },
  };

  // Merge all styles
  const combinedStyles = {
    ...baseStyles,
    ...(sizeStyles[size] || sizeStyles.default),
    ...(variantStyles[variant] || variantStyles.primary),
    ...style,
  };

  // Hover state handler
  const [isHovered, setIsHovered] = React.useState(false);

  const hoverStyles = {
    primary: {
      boxShadow: '0 8px 30px rgba(124, 58, 237, 0.45), 0 0 40px rgba(124, 58, 237, 0.25)',
      transform: 'translateY(-2px)',
    },
    secondary: {
      boxShadow: '0 8px 30px rgba(6, 214, 160, 0.45), 0 0 40px rgba(6, 214, 160, 0.25)',
      transform: 'translateY(-2px)',
    },
    ghost: {
      background: 'rgba(255, 255, 255, 0.08)',
      borderColor: 'rgba(255, 255, 255, 0.2)',
      transform: 'translateY(-2px)',
    },
    danger: {
      boxShadow: '0 8px 30px rgba(239, 68, 68, 0.45), 0 0 40px rgba(239, 68, 68, 0.25)',
      transform: 'translateY(-2px)',
    },
    glass: {
      background: 'rgba(255, 255, 255, 0.08)',
      borderColor: 'rgba(255, 255, 255, 0.15)',
      boxShadow: '0 8px 40px rgba(0, 0, 0, 0.3)',
      transform: 'translateY(-2px)',
    },
  };

  const activeStyles = isHovered && !disabled && !loading
    ? hoverStyles[variant] || hoverStyles.primary
    : {};

  const finalStyles = {
    ...combinedStyles,
    ...activeStyles,
  };

  return (
    <button
      type={type}
      style={finalStyles}
      disabled={disabled || loading}
      aria-disabled={disabled || loading}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
      onMouseDown={(e) => {
        if (!disabled && !loading) {
          e.currentTarget.style.transform = 'scale(0.98)';
        }
      }}
      onMouseUp={(e) => {
        if (!disabled && !loading) {
          e.currentTarget.style.transform = isHovered ? 'translateY(-2px)' : 'translateY(0)';
        }
      }}
      className={className}
      {...props}
    >
      {/* Loading spinner */}
      {loading && (
        <svg
          style={{
            animation: 'spin 1s linear infinite',
            width: '1rem',
            height: '1rem',
          }}
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            style={{ opacity: 0.25 }}
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          />
          <path
            style={{ opacity: 0.75 }}
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      )}

      {/* Icon */}
      {icon && !loading && (
        <span style={{ flexShrink: 0 }}>{icon}</span>
      )}

      {/* Content */}
      <span style={{ position: 'relative', zIndex: 10 }}>{children}</span>

      {/* Add keyframe animation for spinner */}
      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </button>
  );
};

export default Button;

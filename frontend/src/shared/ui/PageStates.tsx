import type { ReactNode } from 'react';
import { Button } from './Button';
import { Icon } from './Icon';
import './ui.css';

export function LoadingState({ label = '불러오는 중…' }: { label?: string }) {
  return (
    <p className="state" role="status">
      {label}
    </p>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div className="state state-error" role="alert">
      <p>{message}</p>
      {onRetry && (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          <Icon name="refresh" size={16} />
          다시 시도
        </Button>
      )}
    </div>
  );
}

export function EmptyState({
  title,
  children,
}: {
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="state">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

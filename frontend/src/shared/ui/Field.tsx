import type { ReactNode } from 'react';
import './ui.css';

/** Label + control (+ optional hint). Put a text or file `<input>` inside. */
export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <label className="field">
      {label}
      {children}
      {hint && <span className="field-hint">{hint}</span>}
    </label>
  );
}

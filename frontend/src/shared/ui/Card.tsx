import type { HTMLAttributes } from 'react';
import './ui.css';

/**
 * light: white card, dark: black highlight card, pending: dashed outline for
 * features that are not available yet.
 */
export function Card({
  tone = 'light',
  className,
  ...props
}: HTMLAttributes<HTMLElement> & { tone?: 'light' | 'dark' | 'pending' }) {
  const classes = ['card', tone !== 'light' && `card-${tone}`, className]
    .filter(Boolean)
    .join(' ');
  return <section className={classes} {...props} />;
}

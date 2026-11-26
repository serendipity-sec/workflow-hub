import type { HTMLAttributes } from 'react';
import './ui.css';

export function Tag({
  tone = 'neutral',
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement> & {
  tone?: 'neutral' | 'dark' | 'outline';
}) {
  const classes = ['tag', tone !== 'neutral' && `tag-${tone}`, className]
    .filter(Boolean)
    .join(' ');
  return <span className={classes} {...props} />;
}

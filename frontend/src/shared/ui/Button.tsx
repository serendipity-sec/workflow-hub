import type { ButtonHTMLAttributes } from 'react';
import { Link } from 'react-router';
import type { LinkProps } from 'react-router';
import './ui.css';

type Look = {
  variant?: 'primary' | 'secondary' | 'ghost';
  size?: 'md' | 'sm';
};

function classes({ variant = 'primary', size = 'md' }: Look, extra?: string) {
  return ['btn', `btn-${variant}`, size === 'sm' && 'btn-sm', extra]
    .filter(Boolean)
    .join(' ');
}

/** The one button style. Use `ButtonLink` when it navigates. */
export function Button({
  variant,
  size,
  className,
  type = 'button',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & Look) {
  return (
    <button
      type={type}
      className={classes({ variant, size }, className)}
      {...props}
    />
  );
}

export function ButtonLink({
  variant,
  size,
  className,
  ...props
}: LinkProps & Look) {
  return <Link className={classes({ variant, size }, className)} {...props} />;
}

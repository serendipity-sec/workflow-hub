/**
 * Decorative soft objects behind the glass panel (pebble, ribbed shape, ring,
 * speckled block). Pure CSS, no images; hidden from assistive technology.
 */
export function Backdrop() {
  return (
    <div className="backdrop" aria-hidden="true">
      <span className="bd-pebble" />
      <span className="bd-ribs" />
      <span className="bd-block" />
      <span className="bd-ring" />
    </div>
  );
}

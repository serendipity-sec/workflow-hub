import type { AbstractValue } from "./value-flow.js";

/**
 * Preserve the possible value's structure through an identity/partial wrapper.
 * The wrapper still owns status, presence, constant, guards, origins and valueId.
 * Never use this for serialization, parsing or an unknown-shape transformation.
 */
export function preserveValueShape(
  wrapper: AbstractValue,
  possible: AbstractValue,
): AbstractValue {
  return {
    ...wrapper,
    fields: possible.fields,
    fieldsComplete: possible.fieldsComplete,
    fullObject: possible.fullObject,
    representativeElement: possible.representativeElement,
    representativeSelection: possible.representativeSelection,
    projectionAlternatives: possible.projectionAlternatives,
    projectionDependencies: possible.projectionDependencies,
    contentComplete: possible.contentComplete,
  };
}

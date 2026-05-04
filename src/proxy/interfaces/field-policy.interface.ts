/**
 * Type for `policy/field-policy.json` (D-06).
 *
 * Outer keys are glob route patterns matched via micromatch.isMatch (first match wins).
 * Inner keys are role names. Inner values are arrays of allowed field names.
 * `["*"]` means all fields pass through (admin convention).
 *
 * Example:
 *   {
 *     "/users/**": { "admin": ["*"], "user": ["id","email","name"] },
 *     "/orders/**": { "admin": ["*"], "user": ["id","status","total"] }
 *   }
 */
export type FieldPolicy = Record<string, Record<string, string[]>>;

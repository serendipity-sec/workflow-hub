import tseslint from "typescript-eslint";

export default [
  { ignores: ["dist/**", "evidence-local/**"] },
  ...tseslint.configs.recommended,
];

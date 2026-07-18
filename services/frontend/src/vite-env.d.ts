/// <reference types="vite/client" />

interface ImportMetaEnv {
  // Injected at build time from the git tag via the APP_VERSION Docker build-arg.
  readonly VITE_APP_VERSION?: string;
}
interface ImportMeta {
  readonly env: ImportMetaEnv;
}

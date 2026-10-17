import antfu from '@antfu/eslint-config'

export default antfu({
  react: true,
  ignores: ['dist', 'coverage', 'src/app/routeTree.gen.ts', 'src/shared/components/ui/**'],
}, {
  // TanStack Router route files export `Route` next to their components.
  files: ['src/app/routes/**/*.tsx'],
  rules: {
    'react-refresh/only-export-components': ['error', { allowExportNames: ['Route'] }],
  },
})

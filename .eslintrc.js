module.exports = {
  env: {
    es6: true,
    node: true,
    mocha: true
  },
  parserOptions: {
    ecmaVersion: 6,
    sourceType: 'module',
    ecmaFeatures: {
      generators: false,
      objectLiteralDuplicateProperties: false
    }
  },
  extends: ['airbnb-base'],
  plugins: [
    "no-only-tests"
  ],
  rules: {
    "max-len": ["warn", 200],
    "import/no-extraneous-dependencies": ["error", { "devDependencies": ["**/test/**/*.js"]}],
    "no-plusplus": "warn",
    "consistent-return": "warn",
    "no-template-curly-in-string": "warn",
    "comma-dangle": "warn",
    "import/no-unresolved": "warn",
    "no-only-tests/no-only-tests": 2
  }
};


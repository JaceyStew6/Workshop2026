#!/bin/sh
# Contrôle avant remise de l'archive : aucun secret en clair, aucune clé privée, .secrets/ absent.
set -eu
cd "$(dirname "$0")/.."
fail=0
[ -d .secrets ] && { echo "KO : dossier .secrets/ présent (à exclure de l'archive)"; fail=1; }
if grep -rIl --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.secrets -E 'AGE-SECRET-KE[Y]-|BEGIN (RSA |EC |OPENSSH )?PRIVATE KE[Y]' . 2>/dev/null | grep -q .; then
  echo "KO : clé privée détectée :"; grep -rIl --exclude-dir=.git --exclude-dir=node_modules -E 'AGE-SECRET-KE[Y]-|BEGIN (RSA |EC |OPENSSH )?PRIVATE KE[Y]' . ; fail=1; fi
if [ -f secrets/secrets.enc.yaml ]; then
  grep -q '^sops:' secrets/secrets.enc.yaml && ! grep -E '^(db_password|jwt_secret|remediation_token|waf_admin_token|probe_password|demo_password|grafana_password): [^E]' secrets/secrets.enc.yaml >/dev/null \
    && echo "OK : secrets/secrets.enc.yaml est chiffré par SOPS" || { echo "KO : secrets.enc.yaml semble en clair"; fail=1; }
fi
if grep -rInE --include='*.yml' --include='*.yaml' --include='*.py' --include='*.sh' --include='*.env' --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.secrets --exclude=secrets.enc.yaml \
   -E '(password|secret|token)[A-Za-z_]*[:=] *["'"'"'][A-Za-z0-9_\-]{16,}["'"'"']' . | grep -v -E 'test|example|_FILE|\$\{|run/secrets' | grep -q .; then
  echo "ATTENTION : valeur ressemblant à un secret codé en dur :"; fail=1; fi
[ "$fail" = 0 ] && echo "OK : aucun secret en clair détecté"
exit $fail

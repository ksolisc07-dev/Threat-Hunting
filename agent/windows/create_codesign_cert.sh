#!/usr/bin/env bash
# Crea un certificado PROPIO de firma de código para el agente (gratis).
# Windows solo confiará en él en los equipos donde instales el .crt.
#
#   ./agent/windows/create_codesign_cert.sh "Tu Nombre u Organización"
#
# Genera en ./codesign/ (¡NUNCA lo subas a GitHub! está en .gitignore):
#   th-codesign.crt      -> certificado público: se instala en los equipos Windows
#   th-codesign.pfx      -> certificado + clave privada (protegido con contraseña)
#   th-codesign.pfx.b64  -> el .pfx en base64: va al secreto CODESIGN_PFX_BASE64 de GitHub
set -euo pipefail
NAME="${1:-Threat Hunting Agent}"
OUT="$(cd "$(dirname "$0")/../.." && pwd)/codesign"
mkdir -p "$OUT"
chmod 700 "$OUT"
cd "$OUT"

if [ -f th-codesign.pfx ]; then
  echo "[!] Ya existe $OUT/th-codesign.pfx; bórralo si quieres generar otro." >&2
  exit 1
fi

PASS="$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-24)"
umask 077

openssl req -x509 -newkey rsa:3072 -sha256 -days 1825 -nodes \
  -keyout th-codesign.key -out th-codesign.crt \
  -subj "/CN=${NAME}/O=${NAME}" \
  -addext "keyUsage=critical,digitalSignature" \
  -addext "extendedKeyUsage=codeSigning" 2>/dev/null

# Cifrado "legacy" del PFX para máxima compatibilidad con signtool/Windows
LEGACY=""
openssl pkcs12 -help 2>&1 | grep -q -- "-legacy" && LEGACY="-legacy"
openssl pkcs12 -export $LEGACY -inkey th-codesign.key -in th-codesign.crt -name "$NAME" \
  -out th-codesign.pfx -passout "pass:${PASS}"
base64 -w0 th-codesign.pfx > th-codesign.pfx.b64
rm -f th-codesign.key
chmod 644 th-codesign.crt

cat <<EOF

[+] Certificado creado en: $OUT
    Editor (publisher): $NAME
    Válido 5 años. Huella SHA1: $(openssl x509 -in th-codesign.crt -noout -fingerprint -sha1 | cut -d= -f2)

==================== PASO SIGUIENTE: secretos en GitHub ====================
GitHub -> repositorio -> Settings -> Secrets and variables -> Actions -> New repository secret

  Nombre: CODESIGN_PFX_BASE64
  Valor:  (todo el contenido de $OUT/th-codesign.pfx.b64)
          cat "$OUT/th-codesign.pfx.b64"

  Nombre: CODESIGN_PASSWORD
  Valor:  ${PASS}

Guarda también la contraseña en un sitio seguro. Quien tenga el .pfx y la
contraseña puede firmar programas en los que tus equipos confiarán.
===========================================================================
EOF

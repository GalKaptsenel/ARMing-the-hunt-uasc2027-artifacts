#!/usr/bin/env bash
# Find, per cell, the smallest sample count that holds the per-bit rate above the target, and the bits per
# second there. Runs a geometric sample ladder and stops at the first rung that clears the target over the
# given rounds.
#
# usage: ./sweep.sh --switch SW --boundary B --medium M --timer T --cpu N [--rounds N] [--target PCT]
#                   [--ladder "a b c ..."] [--sudo]
set -u

bin=./cross_boundary
rounds=20
target=95
cpu=
sw= ; bnd= ; med= ; tmr=
ladder=
use_sudo=0

while [ $# -gt 0 ]; do
    case "$1" in
        --switch)   sw=$2;   shift 2 ;;
        --boundary) bnd=$2;  shift 2 ;;
        --medium)   med=$2;  shift 2 ;;
        --timer)    tmr=$2;  shift 2 ;;
        --cpu)      cpu=$2;  shift 2 ;;
        --rounds)   rounds=$2; shift 2 ;;
        --target)   target=$2; shift 2 ;;
        --ladder)   ladder=$2; shift 2 ;;
        --sudo)     use_sudo=1; shift ;;
        *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

if [ -z "$sw" ] || [ -z "$bnd" ] || [ -z "$med" ] || [ -z "$tmr" ] || [ -z "$cpu" ]; then
    echo "usage: $0 --switch SW --boundary B --medium M --timer T --cpu N [--rounds N] [--target PCT] [--ladder \"...\"] [--sudo]" >&2
    exit 2
fi

if [ -z "$ladder" ]; then
    if [ "$tmr" = cntvct ]; then
        ladder="40 80 160 320 640"
    elif [ "$med" = btb ]; then
        ladder="20 40 80 160"
    elif [ "$med" = l1d ]; then
        ladder="2 6 12 24 48"
    else
        ladder="6 12 24 48 96"
    fi
fi

run=""
[ "$use_sudo" = 1 ] && run="sudo"

printf '%-6s %-8s %-5s %-7s | %-8s %-9s %-9s\n' switch boundary med timer samples perbit bits/s
for n in $ladder; do
    out=$($run $bin --switch "$sw" --boundary "$bnd" --medium "$med" --timer "$tmr" \
                    --cpu "$cpu" --rounds "$rounds" --samples "$n" 2>/dev/null)
    perbit=$(printf '%s\n' "$out" | sed -n 's/.*per-bit rate : [0-9]*\/[0-9]* bits (\([0-9.]*\)%).*/\1/p')
    bps=$(printf '%s\n' "$out" | sed -n 's/.*throughput   : \([0-9]*\) bits\/s.*/\1/p')
    [ -z "$perbit" ] && perbit=0
    [ -z "$bps" ] && bps=0
    printf '%-6s %-8s %-5s %-7s | %-8s %-9s %-9s\n' "$sw" "$bnd" "$med" "$tmr" "$n" "$perbit" "$bps"
    ok=$(awk -v p="$perbit" -v t="$target" 'BEGIN { print (p+0 >= t+0) ? 1 : 0 }')
    if [ "$ok" = 1 ]; then
        echo "  -> holds >= ${target}% at samples=$n (${bps} bits/s)"
        exit 0
    fi
done
echo "  -> did not reach ${target}% within the ladder"
exit 1

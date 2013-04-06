#!/bin/sh

OPERSPEC="Elizacat|alyx|matthew|Mismagius|kyso|j0ah_|CorgiDude|andy"

FSPEC="$1"

echo "users = {
$(sed -nr 's#operator "(.+)" \{#'"'"'\1'"'"'#pg;s#\Wpassword = "(.+)"\;#'"'"'\1'"'"'#pg' $FSPEC |
	xargs -d"\n" -n2 | awk '{ print "\t"$1" : "$2"," }' |
	sed -r "/$OPERSPEC/!d")
}"

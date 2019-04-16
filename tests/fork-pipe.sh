#!/bin/sh

if test "$1" == "child" ; then
echo "spawning process with pipe" | grep pipe
sleep 1
exit 33
fi

echo calling "$0"
sh $0 child &

child=$!
wait $child

exit 42

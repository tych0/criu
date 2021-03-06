# Check how crit de/encodes images
set -e
source `dirname $0`/criu-lib.sh
prep
./test/zdtm.py run --all -f best -x maps04 -x cgroup02 --norst --keep always || fail
PYTHONPATH="$(pwd)/lib/" ./test/crit-recode.py || fail
exit 0

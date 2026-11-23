#!/bin/bash
# VM1: after origin_chain.sh writes CHAIN DONE, run the DuckDB join + aggregate report.
cd /home/afc/afc
until grep -q "CHAIN DONE" data/logs/origin-chain.log 2>/dev/null; do sleep 60; done
grep -q "^ovs finished" data/logs/origin-ovs.log || { echo "ovs not finished, abort $(date -u)"; exit 1; }
~/venv/bin/python -I src/origin.py join --mem 11GB --levels ${LEVELS:-4} && \
~/venv/bin/python -I src/origin.py report --mem 11GB --labels notes/labels_test_0.3.1_final.csv --blobs 4995718753,2f3f552322
echo JOIN DONE rc=$? $(date -u)

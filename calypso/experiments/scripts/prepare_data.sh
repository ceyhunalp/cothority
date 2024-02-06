#!/usr/bin/env bash

### Microbenchmarks

python3.11 process_data.py -p ots ../microbenchmarks/burst/test_data/save/plot/ots.csv burst
python3.11 process_data.py -p pqots ../microbenchmarks/burst/test_data/save/plot/pqots.csv burst
python3.11 process_data.py -p sc ../microbenchmarks/burst/test_data/save/plot/sc.csv burst

python3.11 process_data.py -p ots ../microbenchmarks/protocol/test_data/save/ots.csv micro
python3.11 process_data.py -p pqots ../microbenchmarks/protocol/test_data/save/pqots.csv micro

### Macrobenchmarks

python3.11 process_data.py -p ots ../byzgen/test_data/save/ots_byzgen.csv byzgen
python3.11 process_data.py -p pqots ../byzgen/test_data/save/pqots_byzgen.csv byzgen
python3.11 process_data.py -p sc ../byzgen/test_data/save/semi_byzgen.csv byzgen

python3.11 process_data.py -p ots ../lottery/test_data/save/ots/ots_lot.csv lotto
python3.11 process_data.py -p pqots ../lottery/test_data/save/pqots/pqots_lot.csv lotto
python3.11 process_data.py ../lottery/test_data/save/tournament/tournament.csv lotto

python3.11 process_data.py -p ots ../lottery/test_data/save/ots/ots_batch.csv lotto -b
python3.11 process_data.py -p pqots ../lottery/test_data/save/pqots/pqots_batch.csv lotto -b

# Network Traffic Analyzer

Reads PCAP captures and finds unusual network activity.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Executable: `build/nta`

## Usage

```sh
# Analyze one or more captures
./build/nta analyze capture.pcap [more.pcap...] --db analyze.db --reset

# Or just pass files
./build/nta capture.pcap --db analyze.db --reset
```

Then inspect results:

```sh
./build/nta hosts --db analyze.db
./build/nta conversations --db analyze.db
./build/nta anomalies --db analyze.db
./build/nta report --db analyze.db
```

Default database: `analyze.db` (or set `NTA_DB`).

## Tests

```sh
ctest --test-dir build --output-on-failure
python3 tools/gen_test_pcap.py -o tests/sample.pcap
```

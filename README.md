### Build and Run

The library and tests can be built by
```
./build.sh
```

This will generate `uppid_test` executable in `build/tests` directory. 

To see the list of tests,
```
./uppid_tests -list
```

Each tests can be run as following
```
./uppid_tests -u 3
```
One can test with different set size by setting parameters as
```
./uppid_tests -u 3 -nn 15
```
To see other configurable parameters, please see cpp files in `tests` directory.



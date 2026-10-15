# ICS collection scanner source

These Java and SQL source files document the protocol requests, scheduling logic, and database schemas used to collect ICSLibrary.

| Path | Purpose |
| --- | --- |
| `ScannersMoreTest.java` | Collection entry point |
| `scanners/` | Modbus/TCP, EtherNet/IP, and S7comm request and response handling |
| `schedulers/` | Protocol-specific scanning schedulers |
| `sqls/` | Collection metadata and scanning-log database schemas |

The source was developed for the original collection environment. Running it separately requires its Java dependencies, database configuration, and environment-specific settings. It is not needed for the offline benchmark.

For model-identification experiments, follow the [benchmark instructions](../benchmark/README.md) and use the [released data](https://github.com/sheng710time/ICSLibrary/releases/latest).

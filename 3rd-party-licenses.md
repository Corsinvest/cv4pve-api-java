# License overview of included 3rd party libraries

The project is licensed under the terms of the [LICENSE](LICENSE)

However, it includes several third-party Open-Source libraries, which are licensed under their own respective Open-Source licenses.

## Runtime Dependencies

### Jackson JSON Processor

**License**: Apache License 2.0
**Website**: https://github.com/FasterXML/jackson
**Artifacts**:
- `com.fasterxml.jackson.core:jackson-databind`
- `com.fasterxml.jackson.core:jackson-core`
- `com.fasterxml.jackson.core:jackson-annotations`

Used for JSON parsing and serialization when communicating with Proxmox VE API.

## Test Dependencies

### JUnit 5 (Jupiter)

**License**: Eclipse Public License 2.0
**Website**: https://junit.org/junit5/
**Artifacts**:
- `org.junit.jupiter:junit-jupiter-api`
- `org.junit.jupiter:junit-jupiter-engine`

Used only for testing (not included in distributed artifacts).

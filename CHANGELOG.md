## [1.1.0](https://github.com/zabbix/python-zabbix-utils/compare/v1.0.3...v1.1.0) (2024-01-23)

### Breaking Changes: 

- changed the format of the Sender response
- changed the format of the Getter response

### Features:

- implemented support for specifying Zabbix clusters in Sender
- implemented pre-processing of the agent response

### Bug fixes:

- fixed issue with hiding private (sensitive) fields in the log
- fixed small bugs and flaws

## [1.0.3](https://github.com/zabbix/python-zabbix-utils/compare/v1.0.2...v1.0.3) (2024-01-09)

### Documentation

- added support for Python 3.12
- discontinued support for Python 3.7

### Bug fixes:

- fixed issue with hiding private (sensitive) information in the log.
- fixed small bugs and flaws.

## [1.0.2](https://github.com/zabbix/python-zabbix-utils/compare/v1.0.1...v1.0.2) (2023-12-15)

### Bug fixes:

- added trailing underscores as workaround to use Python keywords as names of API object or method
- changed TypeError to ValueError for the exception during version parsing.
- fixed compression support for Sender and Getter.
- made refactoring of some parts of the code.
- fixed small bugs and flaws.

## [1.0.1](https://github.com/zabbix/python-zabbix-utils/compare/v1.0.0...v1.0.1) (2023-11-27)

### Bug fixes:

- removed deprecated API fields from examples and README.
- removed "Get started" section from README for PyPI.
- fixed small flaws.

## [1.0.0](https://github.com/zabbix/python-zabbix-utils/tree/v1.0.0) (2023-11-17)

Initial release

# Changelog

## [1.6] 2020-05-20
- Use biliard to avoid "daemonic processes are not allowed to have children" in celery
- Restore doc_type="generic_event" used by timesketch even if it'll be deprecated in elastic 8

## [1.5] 2020-05-19
- Little refactoring to improve usage as imported library
- Add threat info to alerts if present
- Updated dependencies
- Added support for pip > 10 build

## [1.4] 2019-10-03
- Support for extracting multiple field as comment
- Keep all meta by default
- Check if elastic is up @deralexxx

## [1.3] 2019-07-29
- Added process-api to processed items
- Skip if not explicitly selected
- Timestamp parsing improvment

## [1.0] 2019-07-24
- First working release
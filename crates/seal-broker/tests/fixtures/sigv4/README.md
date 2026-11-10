# SigV4 test vectors

From the AWS signing test suite in
[awslabs/aws-c-auth](https://github.com/awslabs/aws-c-auth/tree/main/tests/aws-signing-test-suite/v4),
commit `bdb7cef99d8bd1ad3c189b1400140a7787e47105`, under the Apache License 2.0. Only
the header-signing files are kept, because seal never signs query strings.

Left out are the cases seal never signs: paths that need normalising (`.` and `..`
segments, which seal refuses, and the `normalized` variants of repeated slashes), and
`post-sts-header-after`, which adds a session token after signing.

The S3 examples, for single encoding and for chunked uploads, are in the tests
themselves, from the Amazon S3 API reference.

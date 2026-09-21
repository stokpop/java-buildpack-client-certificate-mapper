# Development

The build targets Java 8 bytecode (`maven.compiler` source/target 8); CI builds and tests on Temurin JDK 21.

```shell
$ ./mvnw clean package
```

## CI / Workflows

| Workflow | Trigger | Description |
| -------- | ------- | ----------- |
| **CI** | push to `main`, pull requests, manual | Builds and runs all tests. On push to `main` (after tests pass) also publishes the jar to the rolling snapshot release. |
| **Release** | manual (`workflow_dispatch`) | Bumps to release version, tags `vX.Y.Z`, creates a GitHub Release with the jar attached, then advances to the next SNAPSHOT version. |

All workflows can be triggered from **Actions -> select workflow -> Run workflow**.

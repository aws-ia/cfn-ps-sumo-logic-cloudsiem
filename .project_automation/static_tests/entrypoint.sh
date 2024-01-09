#!/bin/bash -ex

## NOTE: paths may differ when running in a managed task. To ensure behavior is consistent between
# managed and local tasks always use these variables for the project and project type path
PROJECT_PATH=${BASE_PATH}/project
PROJECT_TYPE_PATH=${BASE_PATH}/projecttype

cd $PROJECT_PATH

# Ignoring the following for migration
# All warnings,
# E1019 - Sub validation - false positive for conditionals,
# E2521 - required properties, E3002 - resource properties - false positive for newer resources than pinned CloudFormation resource spec
# E3005 - DependsOn - false positive for conditionals,
# E9101 - Inclusive language check - false positive for database resources
# E3030 - You must specify a valid value for Runtime (python3.11). Valid values are ["dotnet6", "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1", "go1.x", "java11", "java8", "java8.al2", "nodejs", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10", "provided", "provided.al2", "python2.7", "python3.6", "python3.7", "python3.8", "python3.9", "ruby2.5", "ruby2.7"]
cfn-lint --ignore-checks W,E1019,E2521,E3002,E3005,E9101,E3030 -t templates/**/*.yaml -a /tmp/qs-cfn-lint-rules/qs_cfn_lint_rules/

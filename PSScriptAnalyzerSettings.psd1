@{
    # Interactive admin tooling: coloured host output is intentional, so PSAvoidUsingWriteHost
    # is excluded. Everything else uses the default rule set. Target: 0 Warnings and 0 Errors.
    ExcludeRules = @(
        'PSAvoidUsingWriteHost'
    )
}

#Requires -Version 7.0
#Requires -Modules Pester

# Unit tests for the pure functions. Dot-sourcing the script defines its functions but skips
# Main (guarded by $MyInvocation.InvocationName), so no network/Excel is touched.

BeforeAll {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-MDOPhishNoiseReport.ps1')
}

Describe 'Get-MDOBucket' {
    It 'buckets auto-remediated investigationState as Auto-resolved' {
        Get-MDOBucket -InvestigationState 'successfullyRemediated' -Status 'resolved' -AssignedTo '' | Should -Be 'Auto-resolved'
        Get-MDOBucket -InvestigationState 'benign' -Status 'resolved' -AssignedTo '' | Should -Be 'Auto-resolved'
        Get-MDOBucket -InvestigationState 'suppressedAlert' -Status 'resolved' -AssignedTo '' | Should -Be 'Auto-resolved'
    }
    It 'buckets pending/partial investigationState as Escalated' {
        Get-MDOBucket -InvestigationState 'pendingApproval' -Status 'resolved' -AssignedTo '' | Should -Be 'Escalated (manual review)'
        Get-MDOBucket -InvestigationState 'partiallyInvestigated' -Status 'new' -AssignedTo '' | Should -Be 'Escalated (manual review)'
    }
    It 'treats new/inProgress as Escalated' {
        Get-MDOBucket -InvestigationState '' -Status 'inProgress' -AssignedTo '' | Should -Be 'Escalated (manual review)'
    }
    It 'uses the resolved+no-owner proxy for Auto-resolved (proxy)' {
        Get-MDOBucket -InvestigationState '' -Status 'resolved' -AssignedTo '' | Should -Be 'Auto-resolved (proxy)'
    }
    It 'treats resolved with an owner as Manual-resolved' {
        Get-MDOBucket -InvestigationState '' -Status 'resolved' -AssignedTo 'analyst@contoso.com' | Should -Be 'Manual-resolved'
    }
}

Describe 'Get-MDOProp' {
    It 'reads a hashtable key (Graph responses are hashtables)' {
        Get-MDOProp @{ status = 'resolved' } 'status' | Should -Be 'resolved'
    }
    It 'returns the default when the key or object is absent' {
        Get-MDOProp @{ a = 1 } 'missing' 'fallback' | Should -Be 'fallback'
        Get-MDOProp $null 'x' 'fallback' | Should -Be 'fallback'
    }
}

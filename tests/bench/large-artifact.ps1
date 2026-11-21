param([string]$RepoPath = (Join-Path $PSScriptRoot '../..'))
$ErrorActionPreference = 'Stop'
$taskRepo = (Resolve-Path -LiteralPath $RepoPath).Path
$taskBinary = Join-Path $taskRepo 'bin/buildtrace.exe'
Push-Location -LiteralPath $taskRepo
try {
    New-Item -ItemType Directory -Path 'bin' -Force | Out-Null
    $env:GOTOOLCHAIN = 'go1.26.11'
    # Match the production Make/Docker executable flags. Windows maps PE debug
    # sections too; measuring a separate debug build is not the shipped CLI.
    go build -trimpath -ldflags '-s -w' -o $taskBinary ./cmd/buildtrace
    if ($LASTEXITCODE -ne 0) { throw 'CLI build failed' }
    $taskDirectory = Join-Path $taskRepo ('bin/m2-memory-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $taskDirectory | Out-Null
    $taskArtifact = Join-Path $taskDirectory 'artifact.bin'
    $taskManifest = Join-Path $taskDirectory 'manifest.json'
    $taskStatement = Join-Path $taskDirectory 'artifact.intoto.jsonl'
    $taskChunk = [byte[]]::new(1MB)
    $taskHash = [System.Security.Cryptography.IncrementalHash]::CreateHash([System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $taskFile = [System.IO.File]::Open($taskArtifact, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write)
    try {
        for ($taskIndex=0; $taskIndex -lt 1024; $taskIndex++) {
            $taskFile.Write($taskChunk,0,$taskChunk.Length)
            $taskHash.AppendData($taskChunk)
        }
    } finally { $taskFile.Dispose() }
    $taskExpected = [Convert]::ToHexString($taskHash.GetHashAndReset()).ToLowerInvariant()
    $taskHash.Dispose()

    function Invoke-MeasuredCLI([string[]]$Arguments) {
        $taskInfo = [System.Diagnostics.ProcessStartInfo]::new($taskBinary)
        $taskInfo.CreateNoWindow = $true
        $taskInfo.UseShellExecute = $false
        $taskInfo.RedirectStandardOutput = $true
        $taskInfo.RedirectStandardError = $true
        foreach ($taskArgument in $Arguments) { $taskInfo.ArgumentList.Add($taskArgument) }
        $taskProcess = [System.Diagnostics.Process]::Start($taskInfo)
        $taskStdout = $taskProcess.StandardOutput.ReadToEndAsync()
        $taskStderr = $taskProcess.StandardError.ReadToEndAsync()
        $taskPeak = 0L
        $taskClock = [System.Diagnostics.Stopwatch]::StartNew()
        while (-not $taskProcess.WaitForExit(10)) {
            $taskProcess.Refresh()
            $taskPeak = [Math]::Max($taskPeak,$taskProcess.PeakWorkingSet64)
        }
        $taskClock.Stop()
        $taskResult = [pscustomobject]@{ exit=$taskProcess.ExitCode; peak_working_set_bytes=$taskPeak; seconds=$taskClock.Elapsed.TotalSeconds; stdout=$taskStdout.Result; stderr=$taskStderr.Result }
        $taskProcess.Dispose()
        return $taskResult
    }

    $taskCapture = Invoke-MeasuredCLI @('manifest','--repo',$taskRepo,'--artifact',$taskArtifact,'--out',$taskManifest)
    if ($taskCapture.exit -ne 0) { throw $taskCapture.stderr }
    $taskDocument = Get-Content -LiteralPath $taskManifest -Raw | ConvertFrom-Json
    if ($taskDocument.artifacts[0].size -ne 1GB -or $taskDocument.artifacts[0].digest.sha256 -ne $taskExpected) { throw 'Independent SHA-256 or byte count disagrees' }
    $taskVerify = Invoke-MeasuredCLI @('verify','--manifest',$taskManifest,'--root',$taskRepo,'--json')
    if ($taskVerify.exit -ne 0) { throw $taskVerify.stderr }
    $taskRecord = Invoke-MeasuredCLI @('record','--repo',$taskRepo,'--artifact',$taskArtifact,'--out',$taskStatement,'--sign','none')
    if ($taskRecord.exit -ne 0) { throw $taskRecord.stderr }
    $taskProvenance = Get-Content -LiteralPath $taskStatement -Raw | ConvertFrom-Json
    if ($taskProvenance.subject[0].digest.sha256 -ne $taskExpected -or $taskProvenance.predicate.buildDefinition.internalParameters.observedArtifacts[0].size -ne 1GB) { throw 'Recorded subject disagrees with independent digest/byte count' }
    if ($taskProvenance.predicate.runDetails.metadata.startedOn -or $taskProvenance.predicate.runDetails.metadata.finishedOn) { throw 'Original build times were invented' }
    $taskInspection = Invoke-MeasuredCLI @('inspect','--attestation',$taskStatement,'--json')
    if ($taskInspection.exit -ne 0 -or ($taskInspection.stdout | ConvertFrom-Json).scope -ne 'unsigned_statement') { throw 'Unsigned inspection did not report its scope' }
    # Only the long-running 1 GiB hashing processes have a sampled RSS gate.
    foreach ($taskRun in @($taskCapture,$taskVerify,$taskRecord)) {
        if ($taskRun.peak_working_set_bytes -le 0 -or $taskRun.peak_working_set_bytes -ge 64MB) {
            @($taskCapture,$taskVerify,$taskRecord) | Select-Object exit,peak_working_set_bytes,seconds | ConvertTo-Json -Compress | Write-Output
            throw 'Memory measurement is unavailable or exceeds 64 MiB'
        }
    }
    $taskFile = [System.IO.File]::Open($taskArtifact,[System.IO.FileMode]::Open,[System.IO.FileAccess]::ReadWrite)
    try { [void]$taskFile.Seek(512MB,[System.IO.SeekOrigin]::Begin);$taskFile.WriteByte(1) } finally { $taskFile.Dispose() }
    $taskTamper = Invoke-MeasuredCLI @('verify','--manifest',$taskManifest,'--root',$taskRepo,'--json')
    if ($taskTamper.exit -ne 1 -or ($taskTamper.stdout | ConvertFrom-Json).reason -ne 'digest_mismatch') { throw 'Single-byte tamper was not detected' }
    Remove-Item -LiteralPath $taskArtifact
    $taskMissing = Invoke-MeasuredCLI @('verify','--manifest',$taskManifest,'--root',$taskRepo,'--json')
    if ($taskMissing.exit -ne 2) { throw 'Missing artifact did not exit 2' }
    $taskMissingInspection = Invoke-MeasuredCLI @('inspect','--attestation',$taskStatement,'--json')
    if ($taskMissingInspection.exit -ne 0 -or ($taskMissingInspection.stdout | ConvertFrom-Json).status -ne 'inspected') { throw 'Inspection incorrectly depended on the original artifact' }
    $taskResult = [pscustomobject]@{
        artifact_bytes=1GB; sha256=$taskExpected; manifest=$taskCapture; verify=$taskVerify; record=$taskRecord;
        inspect_exit=$taskInspection.exit; inspect_after_artifact_removal_exit=$taskMissingInspection.exit;
        tamper_exit=$taskTamper.exit; missing_exit=$taskMissing.exit;
        method='Windows OS-reported peak working set, polled every 10 ms during each CLI run';
        go_toolchain='go1.26.11'; build_flags='-trimpath -ldflags -s -w (production flags)'; report_directory=$taskDirectory
    }
    $taskJSON = $taskResult | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath (Join-Path $taskDirectory 'result.json') -Value $taskJSON -Encoding utf8NoBOM
    Write-Output $taskJSON
} finally { Pop-Location }

param(
    [Parameter(Mandatory = $false)][switch]$IncludeOwners,
    [Parameter(Mandatory = $false)][switch]$SkipTasks,
    [Parameter(Mandatory = $false)][switch]$SkipWmi,
    [Parameter(Mandatory = $false)][switch]$SkipDrivers,
    [Parameter(Mandatory = $false)][string]$OutputFile = ''
)

$ErrorActionPreference = 'Continue'
$errors = New-Object System.Collections.ArrayList
$result = [ordered]@{
    generated_at = (Get-Date).ToString('o')
    computer = $env:COMPUTERNAME
    user = [Environment]::UserName
    is_admin = $false
    processes = @()
    services = @()
    drivers = @()
    tasks = @()
    startup = @()
    wmi = @()
    errors = @()
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $result.is_admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

function Add-CollectError {
    param([string]$Context, [string]$Message)
    [void]$errors.Add([ordered]@{ context = $Context; message = $Message })
}

# ---------- processes ----------
try {
    $processes = New-Object System.Collections.ArrayList
    foreach ($p in @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)) {
        $owner = ''
        if ($IncludeOwners) {
            try {
                $ownerInfo = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
                if ($ownerInfo -and $ownerInfo.User) {
                    $owner = (($ownerInfo.Domain + '\') + $ownerInfo.User).Trim('\')
                }
            } catch { }
        }
        [void]$processes.Add([ordered]@{
            pid = [int]$p.ProcessId
            ppid = [int]$p.ParentProcessId
            name = [string]$p.Name
            path = [string]$p.ExecutablePath
            cmdline = [string]$p.CommandLine
            user = $owner
            creation = if ($p.CreationDate) { $p.CreationDate.ToString('o') } else { '' }
        })
    }
    $result.processes = @($processes)
} catch {
    Add-CollectError 'processes' $_.Exception.Message
}

# ---------- services ----------
try {
    $services = New-Object System.Collections.ArrayList
    foreach ($s in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        [void]$services.Add([ordered]@{
            name = [string]$s.Name
            display_name = [string]$s.DisplayName
            image_path = [string]$s.PathName
            start_mode = [string]$s.StartMode
            state = [string]$s.State
            account = [string]$s.StartName
            pid = [int]$s.ProcessId
            description = [string]$s.Description
        })
    }
    $result.services = @($services)
} catch {
    Add-CollectError 'services' $_.Exception.Message
}

# ---------- kernel drivers ----------
if (-not $SkipDrivers) {
    try {
        $drivers = New-Object System.Collections.ArrayList
        foreach ($d in @(Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop)) {
            [void]$drivers.Add([ordered]@{
                name = [string]$d.Name
                display_name = [string]$d.DisplayName
                image_path = [string]$d.PathName
                start_mode = [string]$d.StartMode
                state = [string]$d.State
                account = [string]$d.StartName
            })
        }
        $result.drivers = @($drivers)
    } catch {
        Add-CollectError 'drivers' $_.Exception.Message
    }
}

# ---------- scheduled tasks ----------
if (-not $SkipTasks) {
    try {
        $tasks = New-Object System.Collections.ArrayList
        foreach ($t in @(Get-ScheduledTask -ErrorAction Stop)) {
            $actions = New-Object System.Collections.ArrayList
            foreach ($a in @($t.Actions)) {
                [void]$actions.Add([ordered]@{
                    execute = [string]$a.Execute
                    arguments = [string]$a.Arguments
                    working_directory = [string]$a.WorkingDirectory
                })
            }
            $triggers = New-Object System.Collections.ArrayList
            foreach ($tr in @($t.Triggers)) {
                if ($tr) {
                    [void]$triggers.Add([string]$tr.CimClass.CimClassName)
                }
            }
            [void]$tasks.Add([ordered]@{
                name = [string]$t.TaskName
                path = [string]$t.TaskPath
                state = [string]$t.State
                author = [string]$t.Author
                description = [string]$t.Description
                hidden = [bool]$t.Settings.Hidden
                run_as = [string]$t.Principal.UserId
                logon_type = [string]$t.Principal.LogonType
                run_level = [string]$t.Principal.RunLevel
                actions = @($actions)
                triggers = @($triggers)
            })
        }
        $result.tasks = @($tasks)
    } catch {
        Add-CollectError 'tasks' $_.Exception.Message
    }
}

# ---------- startup folders ----------
try {
    $startup = New-Object System.Collections.ArrayList
    $folders = @(
        @{ scope = 'current-user'; path = [Environment]::GetFolderPath('Startup') },
        @{ scope = 'all-users'; path = [Environment]::GetFolderPath('CommonStartup') }
    )
    $shell = $null
    try { $shell = New-Object -ComObject WScript.Shell } catch { }
    foreach ($folder in $folders) {
        if (-not $folder.path -or -not (Test-Path -LiteralPath $folder.path)) { continue }
        foreach ($file in @(Get-ChildItem -LiteralPath $folder.path -File -Force -ErrorAction SilentlyContinue)) {
            $target = ''
            $arguments = ''
            $workingDirectory = ''
            $url = ''
            try {
                if ($file.Extension -ieq '.lnk' -and $shell) {
                    $shortcut = $shell.CreateShortcut($file.FullName)
                    $target = [string]$shortcut.TargetPath
                    $arguments = [string]$shortcut.Arguments
                    $workingDirectory = [string]$shortcut.WorkingDirectory
                } elseif ($file.Extension -ieq '.url') {
                    $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
                    if ($content -match '(?im)^URL=(.+)$') { $url = $Matches[1].Trim() }
                } else {
                    $target = $file.FullName
                }
            } catch { }
            [void]$startup.Add([ordered]@{
                scope = $folder.scope
                name = $file.Name
                path = $file.FullName
                target = $target
                arguments = $arguments
                working_directory = $workingDirectory
                url = $url
            })
        }
    }
    $result.startup = @($startup)
} catch {
    Add-CollectError 'startup' $_.Exception.Message
}

# ---------- WMI event subscription ----------
if (-not $SkipWmi) {
    try {
        $wmi = New-Object System.Collections.ArrayList
        $ns = 'root/subscription'
        $filters = @(Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop)
        $commandConsumers = @(Get-CimInstance -Namespace $ns -ClassName CommandLineEventConsumer -ErrorAction Stop)
        $scriptConsumers = @(Get-CimInstance -Namespace $ns -ClassName ActiveScriptEventConsumer -ErrorAction Stop)
        $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop)
        foreach ($f in $filters) {
            [void]$wmi.Add([ordered]@{
                type = 'EventFilter'
                name = [string]$f.Name
                query = [string]$f.Query
                consumer = ''
            })
        }
        foreach ($c in $commandConsumers) {
            [void]$wmi.Add([ordered]@{
                type = 'CommandLineEventConsumer'
                name = [string]$c.Name
                query = [string]$c.CommandLineTemplate
                consumer = [string]$c.ExecutablePath
            })
        }
        foreach ($c in $scriptConsumers) {
            [void]$wmi.Add([ordered]@{
                type = 'ActiveScriptEventConsumer'
                name = [string]$c.Name
                query = [string]$c.ScriptText
                consumer = [string]$c.ScriptFileName
            })
        }
        foreach ($b in $bindings) {
            [void]$wmi.Add([ordered]@{
                type = 'Binding'
                name = ([string]$b.Filter + ' -> ' + [string]$b.Consumer)
                query = ''
                consumer = ''
            })
        }
        $result.wmi = @($wmi)
    } catch {
        Add-CollectError 'wmi' $_.Exception.Message
    }
}

$result.errors = @($errors)
$json = ConvertTo-Json -InputObject $result -Depth 12 -Compress
if (-not $json) { $json = '{}' }
if (-not $OutputFile) { $OutputFile = Join-Path $env:TEMP ('vcheck-execution-' + [guid]::NewGuid().ToString('N') + '.json') }
[System.IO.File]::WriteAllText($OutputFile, $json, (New-Object System.Text.UTF8Encoding($false)))

Function Start-WindowsUpdate {
    <#
    .SYNOPSIS
		The Install-WindowsUpdate function remotely starts the Install-WindowsUpdate function and returns a "start" object (See outputs below).
		
    .DESCRIPTION
		The Install-WindowsUpdate function remotely starts the Install-WindowsUpdate function and returns a "start" object (See outputs below).
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER AutoReboot
        Automatically reboots the system if a update requires it.
		
    .PARAMETER AutoRun
        Automatically runs the Install-WindowsUpdate function on startup.
		
    .PARAMETER AutoLogin
        Automatically logs into the system after a reboot.
		
    .PARAMETER IncludeRecommended
        Forces recommended (optional) updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeDriver
        Forces driver updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeHidden
        Forces hidden updates to be installed. By default, only important updates are installed.
		
    .PARAMETER Id
        A variable used to group runs and query status information about them.
		
    .PARAMETER VariableName
        Mostly used for testing.
		
    .PARAMETER ShellType
        Mostly used for testing.
		
    .PARAMETER ShellNoExit
        Mostly used for testing.
		
    .PARAMETER AsJob
		Runs the function as a job.
		
	.OUTPUTS
        Returns a "start" object containing:
        -------------------------------------------------------------------------------
        #            : Just a counter for convience.
        ComputerName : The computer name or IP address.
        Result       : Contains "Succeeded" if the Install-WindowsUpdate function was successfully started. Contains "Failed" if wasn't.
        -------------------------------------------------------------------------------

	.EXAMPLE
		Start-WindowsUpdate -ComputerName $computerName -Credential $credential -AutoReboot -AutoRun -AutoLogin
		
		After the proceeding command is executed, the process would be as follows:
		
		01) The Start-WindowsUpdate function starts.
		02) The Start-WindowsUpdate function confirms the computers are online.
		03) The Start-WindowsUpdate function creates a remote session on each of the computers.
		04) In the remote session, the Start-WindowsUpdate function outputs the Install-WindowsUpdate function to the root of C: drive.
		05) In the remote session, the Start-WindowsUpdate function creates a temporary scheduled task to launch the outputted Install-WindowsUpdate function.
		06) In the remote session, the Start-WindowsUpdate function starts the Install-WindowsUpdate function via the scheduled task.
		07) In the remote session, the Start-WindowsUpdate deletes the scheduled task.
		08) The Install-WindowsUpdate function is now running locally as a completely separate process.
		09) The Start-WindowsUpdate function returns a "start" object (defined above in the outputs).
		10) The Start-WindowsUpdate function is complete.
		11) The Install-WindowsUpdate function checks if important windows updates are available.
		12) The Install-WindowsUpdate function installs all important windows updates.
		13) The Install-WindowsUpdate function reboots the system (if required). # -AutoReboot
		14) The user is automatically logged in. # -AutoLogin
		15) The Install-WindowsUpdate function is started again. # -AutoRun
		16) The loop continues until all windows updates are complete.
		17) he Install-WindowsUpdate function is complete.
		
	.EXAMPLE
		Start-WindowsUpdate -ComputerName $computerName -Credential $credential 
		
		After the proceeding command is executed, the process would be as follows:
		
		01) The Start-WindowsUpdate function starts.
		02) The Start-WindowsUpdate function confirms the computers are online.
		03) The Start-WindowsUpdate function creates a remote session on each of the computers.
		04) In the remote session, the Start-WindowsUpdate function outputs the Install-WindowsUpdate function to the root of C: drive.
		05) In the remote session, the Start-WindowsUpdate function creates a temporary scheduled task to launch the outputted Install-WindowsUpdate function.
		06) In the remote session, the Start-WindowsUpdate function starts the Install-WindowsUpdate function via the scheduled task.
		07) In the remote session, the Start-WindowsUpdate deletes the scheduled task.
		08) The Install-WindowsUpdate function is now running locally as a completely separate process.
		09) The Start-WindowsUpdate function returns a "start" object (defined above in the outputs).
		10) The Start-WindowsUpdate function is complete.
		11) The Install-WindowsUpdate function checks if important windows updates are available.
		12) The Install-WindowsUpdate function installs all important windows updates.
		13) The Install-WindowsUpdate function is complete.
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [Switch]
        $AutoReboot,

        [Parameter()]
        [Switch]
        $AutoRun,

        [Parameter()]
        [Switch]
        $AutoLogin,

        [Parameter()]
        [Switch]
        $IncludeRecommended,

        [Parameter()]
        [Switch]
        $IncludeDriver,

        [Parameter()]
        [Switch]
        $IncludeHidden,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Id = [Guid]::NewGuid().Guid.ToUpper(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $VariableName = 'windowsUpdate',

        [Parameter()]
        [ValidateSet('Interactive','PreferInteractive','NonInteractive')]
        [String]
        $ShellType = 'NonInteractive',

        [Parameter()]
        [Switch]
        $ShellNoExit,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get required Install-WindowsUpdate function.
        $functionInstallWindowsUpdate = Get-Item -Path ('function:\\Install-WindowsUpdate') -ErrorAction 'Stop'

        # Get start objects.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
            $AutoReboot
            $AutoRun
            $AutoLogin
            $IncludeRecommended
            $IncludeDriver
            $IncludeHidden
            $Id
            $VariableName
            $ShellType
            $ShellNoExit
            $functionInstallWindowsUpdate
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            $AutoReboot = $args[5]
            $AutoRun = $args[6]
            $AutoLogin = $args[7]
            $IncludeRecommended = $args[8]
            $IncludeDriver = $args[9]
            $IncludeHidden = $args[10]
            $Id = $args[11]
            $VariableName = $args[12]
            $ShellType = $args[13]
            $ShellNoExit = $args[14]
            $functionInstallWindowsUpdate = $args[15]

            # Get computer names online.
            $computerNameOnline = @(
                if ($ComputerName) {
                    ForEach ($computer in $ComputerName) {
                        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                            $computer
                        } else {
                            Write-Warning "${command}: $computer ping failed."
                        }
                    }
                }
            )

            # Get sessions online.
            $sessionOnline = @(
                if ($Session) {
                    ForEach ($sess in $Session) {
                        if ($sess.State -eq 'Opened' -and $sess.Availability -eq 'Available' -and (Test-Connection -ComputerName $sess.ComputerName -Count 1 -Quiet)) {
                            $sess
                        } else {
                            Write-Warning "${command}: $($sess.ComputerName) ping failed."
                        }
                    }
                }
            )
        
            # Get start objects.
            $startObjects = if ($computerNameOnline -or $sessionOnline) {
            
                # Get start objects.
                $param = @{}
                if ($computerNameOnline) {
                    $param.ComputerName = $computerNameOnline
                    $param.Credential = $Credential
                    $param.SessionOption = New-PSSessionOption -NoMachineProfile
                }
                if ($sessionOnline) {
                    $param.Session = $sessionOnline
                }
                $param.ThrottleLimit = 200
                $param.ArgumentList = @(
                    $VerbosePreference
                    $command
                    $Credential
                    $AutoReboot
                    $AutoRun
                    $AutoLogin
                    $IncludeRecommended
                    $IncludeDriver
                    $IncludeHidden
                    $Id
                    $VariableName
                    $ShellType
                    $ShellNoExit
                    $functionInstallWindowsUpdate
                )
                $param.ScriptBlock = {
					
                    # Set variables.
                    $VerbosePreference = $args[0]
                    $command = $args[1]
                    $Credential = $args[2]
                    $AutoReboot = $args[3]
                    $AutoRun = $args[4]
                    $AutoLogin = $args[5]
                    $IncludeRecommended = $args[6]
                    $IncludeDriver = $args[7]
                    $IncludeHidden = $args[8]
                    $Id = $args[9]
                    $VariableName = $args[10]
                    $ShellType = $args[11]
                    $ShellNoExit = $args[12]
                    $functionInstallWindowsUpdate = $args[13]

                    try {

                        # Set environment variables.
                        $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                        # Write verbose.
                        Write-Verbose -Message "${command}: $envComputerName."

                        # Create start object.
                        $startObject = New-Object -TypeName 'psobject'
                        $startObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                        $startObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                        $startObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value 'Failed'

                        # Set script variables.
                        $scriptName = $command
                        $scriptPath = 'C:\' + $command + '.ps1'
                        $autoLoginRemove = $false

                        # Set functions.
                        function Test-UserLoggedIn {
                            [CmdletBinding()]
                            param(
                                [String]$Domain = $env:USERDOMAIN,
                                [String]$User = $env:USERNAME
                            )
                            $explorer = Get-WmiObject -Class 'Win32_Process' -Filter 'Name="explorer.exe"'
                            if ($explorer) {
                                [bool]($explorer.GetOwner() | Where-Object { $_.Domain -eq $Domain -and $_.User -eq $User })
                            } else {
                                $false
                            }
                        }

                        # Get Install-WindowsUpdate function.
                        $functionInstallWindowsUpdateName = $functionInstallWindowsUpdate.Name
                        $functionInstallWindowsUpdateScriptBlock = $functionInstallWindowsUpdate.ScriptBlock
                        $functionInstallWindowsUpdateString = 'function ' + $functionInstallWindowsUpdateName + ' {' + $functionInstallWindowsUpdateScriptBlock + '}'

                        # Get user variables.
                        $domain = if ($Credential.UserName -match '\\') { $Credential.UserName -replace '\\.*' } else { $env:USERDOMAIN }
                        $user = if ($Credential.UserName -match '\\') { $Credential.UserName -replace '.*\\' } else { $env:USERNAME }
                        $password = $Credential.GetNetworkCredential().Password

                        # Get user logged in.
                        $UserLoggedIn = Test-UserLoggedIn -Domain $domain -User $user

                        # Write verbose.
                        if ($ShellType -eq 'Interactive') {
                            # Write-Verbose -Message "${command}: An interactive shell is required."
                        } elseif ($ShellType -eq 'PreferInteractive') {
                            # Write-Verbose -Message "${command}: An interactive shell is prefered."
                        } elseif ($ShellType -eq 'NonInteractive') {
                            # Write-Verbose -Message "${command}: A non-interactive shell is required."
                        }

                        # Write verbose.
                        if ($UserLoggedIn) {

                            # Write-Verbose -Message "${command}: The user '$domain\$user' is currently logged in."
                            if ($ShellType -eq 'Interactive') {
                                # Write-Verbose -Message "${command}: An interactive shell will be launched immediately."
                            } elseif ($ShellType -eq 'PreferInteractive') {
                                # Write-Verbose -Message "${command}: An interactive shell will be launched immediately."
                            } elseif ($ShellType -eq 'NonInteractive') {
                                # Write-Verbose -Message "${command}: A non-interactive shell will be launched immediately."
                            }

                        } else {

                            # Write-Verbose -Message "${command}: The user '$domain\$user' is not currently logged in."
                            if ($ShellType -eq 'Interactive') {
                                # Write-Verbose -Message "${command}: An interactive shell will be launched after reboot and auto login."
                            } elseif ($ShellType -eq 'PreferInteractive') {
                                # Write-Verbose -Message "${command}: A non-interactive shell will be launched immediately."
                            } elseif ($ShellType -eq 'NonInteractive') {
                                # Write-Verbose -Message "${command}: A non-interactive shell will be launched immediately."
                            }

                        }

                        # Set auto login.
                        if (!$UserLoggedIn -and $ShellType -eq 'Interactive') {

                            # Get auto login variables.
                            $winLogonPath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                            $winLogon = Get-ItemProperty -Path $winLogonPath
                            $autoAdminLogon = $winLogon.AutoAdminLogon
                            $autoLogonCount = $winLogon.AutoLogonCount
                            $defaultDomainName = $winLogon.DefaultDomainName
                            $defaultUserName = $winLogon.DefaultUserName
                            $defaultPassword = $winLogon.DefaultPassword

                            # Check if auto login is already set. If so, the script will persist it.
                            if ($autoAdminLogon -ne 1) {
                                # Write-Verbose -Message "${command}: Auto login is not currently set."
                                # Write-Verbose -Message "${command}: Auto login will be removed after reboot."
                                $autoLoginRemove = $true
                            } else {
                                # Write-Verbose -Message "${command}: Auto login is currently set."
                                # Write-Verbose -Message "${command}: Auto login will be persisted after reboot."
                                $autoLoginRemove = $false
                            }

                            # Set auto login.
                            if ($autoAdminLogon -ne 1) {
                                # Write-Verbose -Message "${command}: Set 'AutoAdminLogon' to '1'."
                                New-ItemProperty -Path $winLogonPath -Name 'AutoAdminLogon' -Value '1' -PropertyType 'String' -Force | Out-Null
                            }
                            if ($autoLogonCount -ne $null) {
                                # Write-Verbose -Message "${command}: Remove 'AutoLogonCount'."
                                Remove-ItemProperty -Path $winLogonPath -Name 'AutoLogonCount' -Force | Out-Null
                            }
                            if ($defaultDomainName -ne $domain) {
                                # Write-Verbose -Message "${command}: Set 'DefaultDomainName' to '$domain'."
                                New-ItemProperty -Path $winLogonPath -Name 'DefaultDomainName' -Value $domain -PropertyType 'String' -Force | Out-Null
                            }
                            if ($defaultUserName -ne $user) {
                                # Write-Verbose -Message "${command}: Set 'DefaultUserName' to '$user'."
                                New-ItemProperty -Path $winLogonPath -Name 'DefaultUserName' -Value $user -PropertyType 'String' -Force | Out-Null
                            }
                            if ($defaultPassword -ne $password) {
                                # Write-Verbose -Message "${command}: Set 'DefaultPassword'."
                                New-ItemProperty -Path $winLogonPath -Name 'DefaultPassword' -Value $password -PropertyType 'String' -Force | Out-Null
                            }
                        }

                        # Create the scheduled task.
                        if (!$UserLoggedIn -and $ShellType -eq 'Interactive') {
                        
                            # Interactive shell for user not currently logged in.
                            if ($ShellNoExit) {
                                # Write-Verbose -Message "${command}: Create scheduled task to launch an interactive shell after reboot and auto login with no exit on completion."
                                schtasks /create /tn "$scriptName" /ru "$domain\$User" /sc "onlogon" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                            } else {
                                # Write-Verbose -Message "${command}: Create scheduled task to launch an interactive shell after reboot and auto login."
                                schtasks /create /tn "$scriptName" /ru "$domain\$User" /sc "onlogon" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                            }

                        } elseif ($UserLoggedIn -and ($ShellType -eq 'Interactive' -or $ShellType -eq 'PreferInteractive')) {
                        
                            # Interactive shell for user currently logged in.
                            if ($ShellNoExit) {
                                # Write-Verbose -Message "${command}: Create scheduled task to launch an interactive shell with no exit on completion."
                                schtasks /create /tn "$scriptName" /ru "$domain\$user" /sc "once" /sd "$((Get-Date).AddYears(100).ToString('MM/dd/yyyy'))" /st "$((Get-Date).ToString('HH:mm'))" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                            } else {
                                # Write-Verbose -Message "${command}: Create scheduled task to launch an interactive shell"
                                schtasks /create /tn "$scriptName" /ru "$domain\$user" /sc "once" /sd "$((Get-Date).AddYears(100).ToString('MM/dd/yyyy'))" /st "$((Get-Date).ToString('HH:mm'))" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                            }

                        } else {
                        
                            # Non-Interactive shell.
                            # Write-Verbose -Message "${command}: Create scheduled task to launch a non-interactive shell."
                            schtasks /create /tn "$scriptName" /ru "$domain\$user" /rp "$password" /sc "once" /sd "$((Get-Date).AddYears(100).ToString('MM/dd/yyyy'))" /st "$((Get-Date).ToString('HH:mm'))" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null

                        }

                        # Build the script.
                        # Write-Verbose -Message "${command}: Generate script '$scriptPath'."
                        $script = ''
                
                        # Set verbose.
                        if ($VerbosePreference -eq 'continue') {
                            $script += "`r`n" +
@'
# Set verbose
########################################################
$VerbosePreference = 'continue'
'@ + "`r`n"
                        }

                        # Remove script.
                        $script += "`r`n" +
@"
# Remove script
########################################################
Write-Verbose "Remove script '$scriptPath'."
Remove-Item -Path '$scriptPath' -Force
"@ + "`r`n"
                
                        # Remove scheduled task.
                        $script += "`r`n" +
@"
# Remove scheduled task
########################################################
Write-Verbose "Remove scheduled task '$scriptName'."
schtasks /delete /tn "$scriptName" /f | Out-Null
"@ + "`r`n"
                
                        # Remove auto login.
                        if (!$UserLoggedIn -and $ShellType -eq 'Interactive' -and $autoLoginRemove) {
                            $script += "`r`n" +
@'
# Remove auto login
########################################################
Write-Verbose "Remove auto login."
$winLogonPath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$winLogon = Get-ItemProperty -Path $winLogonPath
$autoAdminLogon = $winLogon.AutoAdminLogon
$defaultPassword = $winLogon.DefaultPassword
if ($autoAdminLogon -ne $null) {
Remove-ItemProperty -Path $winLogonPath -Name 'AutoAdminLogon' -Force | Out-Null
}
if ($defaultPassword -ne $null) {
Remove-ItemProperty -Path $winLogonPath -Name 'DefaultPassword' -Force | Out-Null
}
'@ + "`r`n"
                        }

                        # Automatically run the script after restart auto login.
                        if (!$UserLoggedIn -and $ShellType -eq 'Interactive') {

                            # Wait.
                            $script += "`r`n" +
@'
# Wait
########################################################
$secondsToWait = 20
Write-Verbose "Wait $secondsToWait seconds."
Write-Progress -Activity "Waiting $secondsToWait seconds: (0 of $secondsToWait complete)" -Status ' ' -PercentComplete 0 -Id 0
For($Index = 1; $Index -le $secondsToWait; $Index += 1)
{
Start-Sleep -Seconds 1
$PercentComplete = [Math]::Round(($Index/$secondsToWait)*100,1)
Write-Progress -Activity "Waiting $secondsToWait seconds: ($Index of $secondsToWait complete)" -Status ' ' -PercentComplete $PercentComplete -Id 0
}
Write-Progress -Activity "Waiting $secondsToWait seconds: ($secondsToWait of $secondsToWait complete)" -Status ' ' -PercentComplete 100 -Id 0 -Completed
'@ + "`r`n"
                        }

                        # Import the function.
                        $script += "`r`n"
                        $script += '# Import Install-WindowsUpdate function.' + "`r`n"
                        $script += '########################################################' + "`r`n"
                        $script += '$functionInstallWindowsUpdateString = {' + "`r`n"
                        $script += $functionInstallWindowsUpdateString
                        $script += '}.ToString()' + "`r`n"
                        $script += 'Invoke-Expression -Command $functionInstallWindowsUpdateString' + "`r`n"

                        # Get parameters.
                        $script += "`r`n"
                        $script += '# Get parameters' + "`r`n"
                        $script += '########################################################' + "`r`n"
                        $script += '$param = @{}' + "`r`n"
                        if ($Credential) {
                            $script += '$param.Credential = New-Object -TypeName ''System.Management.Automation.PSCredential'' -ArgumentList @(''' + $domain + '\' + $user + ''',(ConvertTo-SecureString -String ''' + $password + ''' -AsPlainText -Force))' + "`r`n"
                        }
                        if ($AutoReboot) {
                            $script += '$param.AutoReboot = $true' + "`r`n"
                        }
                        if ($AutoRun) {
                            $script += '$param.AutoRun = $true' + "`r`n"
                        }
                        if ($AutoLogin) {
                            $script += '$param.AutoLogin = $true' + "`r`n"
                        }
                        if ($IncludeRecommended) {
                            $script += '$param.IncludeRecommended = $true' + "`r`n"
                        }
                        if ($IncludeDriver) {
                            $script += '$param.IncludeDriver = $true' + "`r`n"
                        }
                        if ($IncludeHidden) {
                            $script += '$param.IncludeHidden = $true' + "`r`n"
                        }
                        if ($Id) {
                            $script += '$param.Id = ''' + $Id + '''' + "`r`n"
                        }
                        if ($VariableName) {
                            $script += '$param.VariableName = ''' + $VariableName + '''' + "`r`n"
                        }
               
                        # Run the function.
                        $script += "`r`n"
                        $script += '# Run Install-WindowsUpdate function' + "`r`n"
                        $script += '########################################################' + "`r`n"
                        $script += '$' + $VariableName + ' = ' + "$functionInstallWindowsUpdateName @param" + "`r`n"

                        # Output the script.
                        $script -replace "(?<!`r)`n","`r`n" | Out-File -FilePath $scriptPath -Width 8192 -Force

                        # Run the output script.
                        if (!$UserLoggedIn -and $ShellType -eq 'Interactive') {
                            # Write-Verbose -Message "${command}: Restart computer and launch scheduled task '$scriptName'."
                            Restart-Computer

                        } else {
                            # Write-Verbose -Message "${command}: Launch scheduled task '$scriptName'."
                            schtasks /end /tn "$scriptName" > $null 2>&1
                            Start-Sleep -Seconds 1
                            cmd /c schtasks /run /tn "$scriptName" | Out-Null
                        }

                        # Set result.
                        $startObject.Result = 'Succeeded'

                        # Return start object.
                        $startObject

                    } catch {

                        # Write error.
                        Write-Error -ErrorRecord $_   

                    }
                }
                try {
                    Invoke-Command @param
                } catch {
                    Write-Warning "${command}: $($_.TargetObject) session failed."
                }
            }

            # Return start objects.
            if ($startObjects) {
            
                # Add ComputerName to start objects.
                $count = 0
                ForEach($startObject in $startObjects) {
                    $startObject.ComputerName = $startObjects[$count].PSComputerName
                    $count += 1
                }

                # Sort start objects.
                $startObjects = $startObjects | Sort-Object -Property 'ComputerName'
            
                # Add # to start object containers.
                $count = 1
                ForEach($startObject in $startObjects) {
                    $startObject.'#' = $count
                    $count += 1
                }

                # Exclude pscomputername, psshowcomputername, and runspaceid.
                $startObjects = $startObjects | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                # Return start objects.
                $startObjects
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Install-WindowsUpdate {
    <#
    .SYNOPSIS
        The Install-WindowsUpdate function installs windows updates.
		
		Each execution of the Install-WindowsUpdate function generates a "run" object which is stored locally in program data as xml files.  They can be queried anytime during or after the run by using the associated Id with the Get-WindowsUpdateStatus function.
		
    .DESCRIPTION
        The Install-WindowsUpdate function installs windows updates.
		
		Each execution of the Install-WindowsUpdate function generates a "run" object which is stored locally in program data as xml files.  They can be queried anytime during or after the run by using the associated Id with the Get-WindowsUpdateStatus function.

    .PARAMETER Credential
        The credentials to use to connect to the computer(s).

    .PARAMETER AutoReboot
        Automatically reboots the system if a update requires it.
		
    .PARAMETER AutoRun
        Automatically runs the Install-WindowsUpdate function on startup.
		
    .PARAMETER AutoLogin
        Automatically logs into the system after a reboot.
		
    .PARAMETER IncludeRecommended
        Forces recommended (optional) updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeDriver
        Forces driver updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeHidden
        Forces hidden updates to be installed. By default, only important updates are installed.
		
    .PARAMETER Id
        A variable used to group runs and query status information about them.
		
    .PARAMETER VariableName
        Mostly used for testing.
		
	.OUTPUTS
		Returns a "run" object. There are a lot of nested objects and properties so it is probably best to explore them for yourself.
		
		Regardless, here is an example "run" object. The indented properties are nested objects.
		-------------------------------------------------------------------------------
		ComputerName   : mycomputer.domain.com
		Number         : 1
		Version        : 1
		FreeSpaceGB    : 184.76
		Domain         : domain.com
		OS             : Windows Server 2019 Datacenter
		PSVersion      : 5.1.14409.1018
		UpdateRetryRun : False
		UpdateCount    : 9
		StopFile       : False
		State          : Complete
		Result         : Succeeded
		Reboot         : True
		Start          : 2/21/2020 9:08:20 AM
		End            : 2/21/2020 9:17:00 AM
		Duration       : 00:08:39.1725551
		
		Parameter      : 
		--------------------------
			Id                 : 20200221
			Credential         : domain\administrator
			AutoReboot         : False
			AutoRun            : False
			AutoLogin          : False
			IncludeRecommended : False
			IncludeDriver      : False
			IncludeHidden      : False
			VariableName       : windowsUpdate

		Update         : 
		--------------------------
			Title    : 2020-02 Cumulative Security Update for Internet Explorer 11 for Windows Server 2012 R2 for x64-based systems
			Number   : 9
			SizeMB   : 55.03
			Category : Security Updates
			Severity : Moderate
			KB       : 4537767
			Bulletin :
			
			Download : 
			--------------------------
				Result   : @{Code=2; Description=Succeeded}
				HResult  : @{Code=0; Hexadecimal=0x0; Message=Succeeded; Description=The Operation succeeded.; Mitigation=}
				State    : Complete
				Start    : 2/21/2020 9:15:34 AM
				End      : 2/21/2020 9:15:34 AM
				Duration : 00:00:00.3437542
				
			Install  : 
			--------------------------
				Result   : @{Code=2; Description=Succeeded}
				HResult  : @{Code=0; Hexadecimal=0x0; Message=Succeeded; Description=The Operation succeeded.; Mitigation=}
				State    : Complete
				Start    : 2/21/2020 9:15:34 AM
				End      : 2/21/2020 9:16:14 AM
				Duration : 00:00:39.8598754
				
			Percent  : 100
			State    : Complete
			Result   : Succeeded
			Reboot   : True
			Start    : 2/21/2020 9:16:14 AM
			End      : 2/21/2020 9:17:00 AM
			Duration : 00:00:45.5318690

		Status         : 
		--------------------------
			Message : Download '2020-02 Cumulative Security Update for Internet Explorer 11 for Windows Server 2012 R2 for
					  x64-based systems (KB4537767)' completed with status 'Succeeded' in 1 Second.
			Code    : 1
			Step    : 7
			Update  : @{Title=2020-02 Cumulative Security Update for Internet Explorer 11 for Windows Server 2012 R2 for x64-based
					  systems; Number=9; SizeMB=55.03; Category=Security Updates; Severity=Moderate; KB=4537767; Bulletin=;
					  Download=; Install=; Percent=100; State=Complete; Result=Succeeded; Reboot=True; Start=2/21/2020 9:16:14 AM;
					  End=2/21/2020 9:17:00 AM; Duration=00:00:45.5318690}
	
	-------------------------------------------------------------------------------
	
	.EXAMPLE
		Install-WindowsUpdate -Credential $credential -AutoReboot -AutoRun -AutoLogin
		
		01) The Install-WindowsUpdate function checks if important windows updates are available.
		02) The Install-WindowsUpdate function installs all important windows updates.
		03) The Install-WindowsUpdate function reboots the system (if required). # -AutoReboot
		04) The user is automatically logged in. # -AutoLogin
		05) The Install-WindowsUpdate function is started again. # -AutoRun
		06) The loop continues until all windows updates are complete.
		07) The Install-WindowsUpdate function is complete.
		
	.EXAMPLE
		Install-WindowsUpdate
		
		01) The Install-WindowsUpdate function checks if important windows updates are available.
		02) The Install-WindowsUpdate function installs all important windows updates.
		03) The Install-WindowsUpdate function is complete.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter()]
        [Switch]
        $AutoReboot,

        [Parameter()]
        [Switch]
        $AutoRun,

        [Parameter()]
        [Switch]
        $AutoLogin,

        [Parameter()]
        [Switch]
        $IncludeRecommended,

        [Parameter()]
        [Switch]
        $IncludeDriver,

        [Parameter()]
        [Switch]
        $IncludeHidden,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Id = [Guid]::NewGuid().Guid.ToUpper(),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $VariableName = 'windowsUpdate'
    )

    try {
        # Import windows update error function.
        function Get-WindowsUpdateError {
            [CmdletBinding()]
            param (
                [Int]$hResult = 0
            )

            $object = New-Object -TypeName 'psobject'
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Hexadecimal' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Message' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Description' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Mitigation' -Value ''

            if ($PSBoundParameters.ContainsKey('hResult')) {

                $hexString = '0x' + ($hResult).ToString('X')

                switch -exact ($hexString) {
                    '0x0'        { $message = 'Succeeded'; $description = 'The Operation succeeded.'; $mitigation=''; break }
                    '0x00240001' { $message = 'WU_S_SERVICE_STOP'; $description = 'Windows Update Agent was stopped successfully.'; $mitigation=''; break }
                    '0x00240002' { $message = 'WU_S_SELFUPDATE'; $description = 'Windows Update Agent updated itself.'; $mitigation=''; break }
                    '0x00240003' { $message = 'WU_S_UPDATE_ERROR'; $description = 'Operation completed successfully but there were errors applying the updates.'; $mitigation=''; break }
                    '0x00240004' { $message = 'WU_S_MARKED_FOR_DISCONNECT'; $description = 'A callback was marked to be disconnected later because the request to disconnect the Operation came while a callback was executing.'; $mitigation=''; break }
                    '0x00240005' { $message = 'WU_S_REBOOT_REQUIRED'; $description = 'The system must be restarted to complete installation of the update.'; $mitigation=''; break }
                    '0x00240006' { $message = 'WU_S_ALREADY_INSTALLED'; $description = 'The update to be installed is already installed on the system.'; $mitigation=''; break }
                    '0x00240007' { $message = 'WU_S_ALREADY_UNINSTALLED'; $description = 'The update to be removed is not installed on the system.'; $mitigation=''; break }
                    '0x00240008' { $message = 'WU_S_ALREADY_DOWNLOADED'; $description = 'The update to be downloaded has already been downloaded.'; $mitigation=''; break }
                    '0x80240001' { $message = 'WU_E_NO_SERVICE'; $description = 'Windows Update Agent was unable to provide the service.'; $mitigation=''; break }
                    '0x80240002' { $message = 'WU_E_MAX_CAPACITY_REACHED'; $description = 'The maximum capacity of the service was exceeded.'; $mitigation=''; break }
                    '0x80240003' { $message = 'WU_E_UNKNOWN_ID'; $description = 'An ID cannot be found.'; $mitigation=''; break }
                    '0x80240004' { $message = 'WU_E_NOT_INITIALIZED'; $description = 'The object could not be initialized.'; $mitigation=''; break }
                    '0x80240005' { $message = 'WU_E_RANGEOVERLAP'; $description = 'The update handler requested a byte range overlapping a previously requested range.'; $mitigation=''; break }
                    '0x80240006' { $message = 'WU_E_TOOMANYRANGES'; $description = 'The requested number of byte ranges exceeds the maximum number (2^31 - 1).'; $mitigation=''; break }
                    '0x80240007' { $message = 'WU_E_INVALIDINDEX'; $description = 'The index to a collection was invalid.'; $mitigation=''; break }
                    '0x80240008' { $message = 'WU_E_ITEMNOTFOUND'; $description = 'The key for the item queried could not be found.'; $mitigation=''; break }
                    '0x80240009' { $message = 'WU_E_OperationINPROGRESS'; $description = 'Another conflicting Operation was in progress. Some Operations such as installation cannot be performed twice simultaneously.'; $mitigation=''; break }
                    '0x8024000A' { $message = 'WU_E_COULDNOTCANCEL'; $description = 'Cancellation of the Operation was not allowed.'; $mitigation=''; break }
                    '0x8024000C' { $message = 'WU_E_NOOP'; $description = 'No Operation was required.'; $mitigation=''; break }
                    '0x8024000D' { $message = 'WU_E_XML_MISSINGDATA'; $description = 'Windows Update Agent could not find required information in the update''s XML data.'; $mitigation=''; break }
                    '0x8024000F' { $message = 'WU_E_CYCLE_DETECTED'; $description = 'Circular update relationships were detected in the metadata.'; $mitigation=''; break }
                    '0x80240010' { $message = 'WU_E_TOO_DEEP_RELATION'; $description = 'Update relationships too deep to evaluate were evaluated.'; $mitigation=''; break }
                    '0x80240011' { $message = 'WU_E_INVALID_RELATIONSHIP'; $description = 'An invalid update relationship was detected.'; $mitigation=''; break }
                    '0x80240012' { $message = 'WU_E_REG_VALUE_INVALID'; $description = 'An invalid registry value was read.'; $mitigation=''; break }
                    '0x80240013' { $message = 'WU_E_DUPLICATE_ITEM'; $description = 'Operation tried to add a duplicate item to a list.'; $mitigation=''; break }
                    '0x80240016' { $message = 'WU_E_INSTALL_NOT_ALLOWED'; $description = 'Operation tried to install while another installation was in progress or the system was pending a mandatory restart.'; $mitigation=''; break }
                    '0x80240017' { $message = 'WU_E_NOT_APPLICABLE'; $description = 'Operation was not performed because there are no applicable updates.'; $mitigation=''; break }
                    '0x80240018' { $message = 'WU_E_NO_USERTOKEN'; $description = 'Operation failed because a required user token is missing.'; $mitigation=''; break }
                    '0x80240019' { $message = 'WU_E_EXCLUSIVE_INSTALL_CONFLICT'; $description = 'An exclusive update cannot be installed with other updates at the same time.'; $mitigation=''; break }
                    '0x8024001A' { $message = 'WU_E_POLICY_NOT_SET'; $description = 'A policy value was not set.'; $mitigation=''; break }
                    '0x8024001B' { $message = 'WU_E_SELFUPDATE_IN_PROGRESS'; $description = 'The Operation could not be performed because the Windows Update Agent is self-updating.'; $mitigation=''; break }
                    '0x8024001D' { $message = 'WU_E_INVALID_UPDATE'; $description = 'An update contains invalid metadata.'; $mitigation=''; break }
                    '0x8024001E' { $message = 'WU_E_SERVICE_STOP'; $description = 'Operation did not complete because the service or system was being shut down.'; $mitigation=''; break }
                    '0x8024001F' { $message = 'WU_E_NO_CONNECTION'; $description = 'Operation did not complete because the network connection was unavailable.'; $mitigation=''; break }
                    '0x80240021' { $message = 'WU_E_TIME_OUT'; $description = 'Operation did not complete because it timed out.'; $mitigation=''; break }
                    '0x80240022' { $message = 'WU_E_ALL_UPDATES_FAILED'; $description = 'Operation failed for all the updates.'; $mitigation=''; break }
                    '0x80240023' { $message = 'WU_E_EULAS_DECLINED'; $description = 'The license terms for all updates were declined.'; $mitigation=''; break }
                    '0x80240024' { $message = 'WU_E_NO_UPDATE'; $description = 'There are no updates.'; $mitigation=''; break }
                    '0x80240025' { $message = 'WU_E_USER_ACCESS_DISABLED'; $description = 'Group Policy settings prevented access to Windows Update.'; $mitigation=''; break }
                    '0x80240026' { $message = 'WU_E_INVALID_UPDATE_TYPE'; $description = 'The type of update is invalid.'; $mitigation=''; break }
                    '0x80240027' { $message = 'WU_E_URL_TOO_LONG'; $description = 'The URL exceeded the maximum length.'; $mitigation=''; break }
                    '0x80240028' { $message = 'WU_E_UNINSTALL_NOT_ALLOWED'; $description = 'The update could not be uninstalled because the request did not originate from a WSUS server.'; $mitigation=''; break }
                    '0x80240029' { $message = 'WU_E_INVALID_PRODUCT_LICENSE'; $description = 'Search may have missed some updates before there is an unlicensed application on the system.'; $mitigation=''; break }
                    '0x8024002A' { $message = 'WU_E_MISSING_HANDLER'; $description = 'A component required to detect applicable updates was missing.'; $mitigation=''; break }
                    '0x8024002B' { $message = 'WU_E_LEGACYSERVER'; $description = 'An Operation did not complete because it requires a newer version of server.'; $mitigation=''; break }
                    '0x8024002C' { $message = 'WU_E_BIN_SOURCE_ABSENT'; $description = 'A delta-compressed update could not be installed because it required the source.'; $mitigation=''; break }
                    '0x8024002D' { $message = 'WU_E_SOURCE_ABSENT'; $description = 'A full-file update could not be installed because it required the source.'; $mitigation=''; break }
                    '0x8024002E' { $message = 'WU_E_WU_DISABLED'; $description = 'Access to an unmanaged server is not allowed.'; $mitigation=''; break }
                    '0x8024002F' { $message = 'WU_E_CALL_CANCELLED_BY_POLICY'; $description = 'Operation did not complete because the DisableWindowsUpdateAccess policy was set.'; $mitigation=''; break }
                    '0x80240030' { $message = 'WU_E_INVALID_PROXY_SERVER'; $description = 'The format of the proxy list was invalid.'; $mitigation=''; break }
                    '0x80240031' { $message = 'WU_E_INVALID_FILE'; $description = 'The file is in the wrong format.'; $mitigation=''; break }
                    '0x80240032' { $message = 'WU_E_INVALID_CRITERIA'; $description = 'The search criteria string was invalid.'; $mitigation=''; break }
                    '0x80240033' { $message = 'WU_E_EULA_UNAVAILABLE'; $description = 'License terms could not be downloaded.'; $mitigation=''; break }
                    '0x80240034' { $message = 'WU_E_DOWNLOAD_FAILED'; $description = 'Update failed to download.'; $mitigation=''; break }
                    '0x80240035' { $message = 'WU_E_UPDATE_NOT_PROCESSED'; $description = 'The update was not processed.'; $mitigation=''; break }
                    '0x80240036' { $message = 'WU_E_INVALID_Operation'; $description = 'The object''s current state did not allow the Operation.'; $mitigation=''; break }
                    '0x80240037' { $message = 'WU_E_NOT_SUPPORTED'; $description = 'The functionality for the Operation is not supported.'; $mitigation=''; break }
                    '0x80240038' { $message = 'WU_E_WINHTTP_INVALID_FILE'; $description = 'The downloaded file has an unexpected content type.'; $mitigation=''; break }
                    '0x80240039' { $message = 'WU_E_TOO_MANY_RESYNC'; $description = 'Agent is asked by server to resync too many times.'; $mitigation=''; break }
                    '0x80240040' { $message = 'WU_E_NO_SERVER_CORE_SUPPORT'; $description = 'WUA API method does not run on Server Core installation.'; $mitigation=''; break }
                    '0x80240041' { $message = 'WU_E_SYSPREP_IN_PROGRESS'; $description = 'Service is not available while sysprep is running.'; $mitigation=''; break }
                    '0x80240042' { $message = 'WU_E_UNKNOWN_SERVICE'; $description = 'The update service is no longer registered with AU.'; $mitigation=''; break }
                    '0x80240043' { $message = 'WU_E_NO_UI_SUPPORT'; $description = 'There is no support for WUA UI.'; $mitigation=''; break }
                    '0x80240FFF' { $message = 'WU_E_UNEXPECTED'; $description = 'An Operation failed due to reasons not covered by another error code.'; $mitigation=''; break }
                    '0x8024402F' { $message = 'WU_E_PT_ECP_SUCCEEDED_WITH_ERRORS'; $description = 'External cab file processing completed with some errors.'; $mitigation='One of the reasons we see this issue is due to the design of a software called Lightspeed Rocket for Web filtering. The IP addresses of the computers you want to get updates successfully on, should be added to the exceptions list of Lightspeed'; break }
                    '0x80242006' { $message = 'WU_E_UH_INVALIDMETADATA'; $description = 'A handler Operation could not be completed because the update contains invalid metadata.'; $mitigation='Rename Software Redistribution Folder and attempt to download the updates again: Rename the following folders to *.BAK: - %systemroot%\system32\catroot2 To do this, type the following commands at a command prompt. Press ENTER after you type each command. - Ren %systemroot%\SoftwareDistribution\DataStore *.bak - Ren %systemroot%\SoftwareDistribution\Download *.bak Ren %systemroot%\system32\catroot2 *.bak'; break }
                    '0x80070BC9' { $message = 'ERROR_FAIL_REBOOT_REQUIRED'; $description = 'The requested Operation failed. A system reboot is required to roll back changes made.'; $mitigation='Ensure that we do not have any policies that control the start behavior for the Windows Module Installer. This service should not be hardened to any start value and should be managed by the OS.'; break }
                    '0x80200053' { $message = 'BG_E_VALIDATION_FAILED'; $description = 'NA.'; $mitigation='Ensure that there is no Firewalls that filter downloads. The Firewall filtering may lead to invalid responses being received by the Windows Update Client. If the issue still persists, run the WU reset script.'; break }
                    '0x80072EE2' { $message = 'WININET_E_TIMEOUT'; $description = 'The Operation timed out.'; $mitigation='This error message can be caused if the computer isn''t connected to Internet. To fix this issue, following these steps: make sure these URLs are not blocked: http://.update.microsoft.com https://.update.microsoft.com http://download.windowsupdate.com Additionally , you can take a network trace and see what is timing out. <Refer to Firewall Troubleshooting scenario>'; break }
                    '0x80072EFD' { $message = 'TIME OUT ERRORS'; $description = 'The Operation timed out.'; $mitigation='Make sure there are no firewall rules or proxy to block Microsoft download URLs. Take a network monitor trace to understand better. <Refer to Firewall Troubleshooting scenario>'; break }
                    '0x80072EFE' { $message = 'TIME OUT ERRORS'; $description = 'The Operation timed out.'; $mitigation='Make sure there are no firewall rules or proxy to block Microsoft download URLs. Take a network monitor trace to understand better. <Refer to Firewall Troubleshooting scenario>'; break }
                    '0x80D02002' { $message = 'TIME OUT ERRORS'; $description = 'The Operation timed out.'; $mitigation='Make sure there are no firewall rules or proxy to block Microsoft download URLs. Take a network monitor trace to understand better. <Refer to Firewall Troubleshooting scenario>'; break }
                    '0X8007000D' { $message = 'ERROR_INVALID_DATA'; $description = 'Indicates invalid data downloaded or corruption occurred.'; $mitigation='Attempt to re-download the update and initiate installation.'; break }
                    '0x8024A10A' { $message = 'USO_E_SERVICE_SHUTTING_DOWN'; $description = 'Indicates that the WU Service is shutting down.'; $mitigation='This may happen due to a very long period of time of inactivity, a system hang leading to the service being idle and leading to the shutdown of the service. Ensure that the system remains active and the connections remain established to complete the upgrade.'; break }
                    '0x80240020' { $message = 'WU_E_NO_INTERACTIVE_USER'; $description = 'Operation did not complete because there is no logged-on interactive user.'; $mitigation='Please login to the system to initiate the installation and allow the system to be rebooted.'; break }
                    '0x80242014' { $message = 'WU_E_UH_POSTREBOOTSTILLPENDING'; $description = 'The post-reboot Operation for the update is still in progress.'; $mitigation='Some Windows Updates require the system to be restarted. Reboot the system to complete the installation of the Updates.'; break}
                    '0x80246017' { $message = 'WU_E_DM_UNAUTHORIZED_LOCAL_USER'; $description = 'The download failed because the local user was denied authorization to download the content.'; $mitigation='Ensure that the user attempting to download and install updates has been provided with sufficient privileges to install updates (Local Administrator).'; break }
                    '0x8024000B' { $message = 'WU_E_CALL_CANCELLED'; $description = 'Operation was cancelled.'; $mitigation='This indicates that the Operation was cancelled by the user/service. You may also encounter this error when we are unable to filter the results. Run the Decline Superseded PowerShell script to allow the filtering process to complete.'; break }
                    '0x8024000E' { $message = 'WU_E_XML_INVALID'; $description = 'Windows Update Agent found invalid information in the update''s XML data.'; $mitigation='Certain drivers contain additional metadata information in the update.xml, which could lead Orchestrator to understand it as invalid data. Ensure that you have the latest Windows Update Agent installed on the machine.'; break }
                    '0x8024D009' { $message = 'WU_E_SETUP_SKIP_UPDATE'; $description = 'An update to the Windows Update Agent was skipped due to a directive in the wuident.cab file.'; $mitigation='You may encounter this error when WSUS is not sending the Self-update to the clients. Review KB920659 for instructions to resolve the issue.'; break }
                    '0x80244007' { $message = 'WU_E_PT_SOAPCLIENT_SOAPFAULT'; $description = 'SOAP client failed because there was a SOAP fault for reasons of WU_E_PT_SOAP_* error codes.'; $mitigation='This issue occurs because Windows cannot renew the cookies for Windows Update. Review KB2883975 for instructions to resolve the issue.'; break }
                    default      { $message = 'Failed'; $description = 'The Operation failed.'; $mitigation=''; break }
                }

                $object.Code = $hResult
                $object.Hexadecimal = $hexString
                $object.Message = $message
                $object.Description = $description
                $object.Mitigation = $mitigation
            }

            $object
        }

        # Create export run object function.
        function Export-RunObject {
            Export-Clixml -InputObject $runObject -Path $runObjectPath -Force -ErrorAction 'SilentlyContinue'
        }

        # Create out status function.
        function Out-Status {
            [CmdletBinding()]
            param(
                [String]$Message = '',
                [Int]$Code = 0,
                [Int]$Step = 0,
                [Switch]$NoExport
            )

            # Create object.
            $object = New-Object -TypeName 'psobject'
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Message' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Step' -Value ''
            $object | Add-Member -MemberType 'NoteProperty' -Name 'Update' -Value ''

            # Message
            if ($PSBoundParameters.ContainsKey('Message')) {
                $object.Message = $Message
            }

            # Code
            if ($PSBoundParameters.ContainsKey('Code')) {
                $object.Code = $Code
                <#
                $object.CodeString = switch -exact ($Code) {
                    0       { 'Default' ; break }
                    1       { 'Success' ; break }
                    2       { 'Warning' ; break }
                    3       { 'Error'   ; break }
                    default { 'Unknown' ; break }
                }
                #>
            }

            # Step
            if ($PSBoundParameters.ContainsKey('Step')) {
                $object.Step = $Step
                <#
                $object.StepString = switch -exact ($Step) {
                    0       { 'Default'                                            ; break }
                    1       { 'Check if this is a first run or reboot run.'        ; break }
                    2       { 'Check available free space.'                        ; break }
                    3       { 'Check if the windows update service is enabled.'    ; break }
                    4       { 'Check if previous windows update require a reboot.' ; break }
                    5       { 'Check if the windows update installer is ready.'    ; break }
                    6       { 'Check if windows updates are available.'            ; break }
                    7       { 'Download and install windows updates.'              ; break }
                    8       { 'Reboot computer.'                                   ; break }
                    9       { 'Script complete.'                                   ; break }
                    default { 'Unknown'                                            ; break }
                }
                #>
            }

            # Update
            if ($PSBoundParameters.ContainsKey('Step') -and $Step -eq 7 -and $updateObject) {
                $object.Update = $updateObject
            }

            # Append to run object.
            $runObject.Status += $object

            # Export.
            if (!$NoExport) {
                Export-RunObject
            }
        }

        # Create format time span funtion.
        function Format-TimeSpanString {
            [CmdletBinding()]
            param(
                [TimeSpan]$TimeSpan
            )
    
            $string = ''
            if ($TimeSpan.Days) { $string += "$($TimeSpan.Days) Day" ; if ($TimeSpan.Days -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
            if ($TimeSpan.Hours) { $string += "$($TimeSpan.Hours) Hour" ; if ($TimeSpan.Hours -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
            if ($TimeSpan.Minutes) { $string += "$($TimeSpan.Minutes) Minute" ; if ($TimeSpan.Minutes -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
            if ($TimeSpan.Seconds) { $string += "$($TimeSpan.Seconds) Second" ; if ($TimeSpan.Seconds -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
            #if ($TimeSpan.Milliseconds) { $string += "$($TimeSpan.Milliseconds) Millisecond" ; if ($TimeSpan.Days -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
            if (!$TimeSpan.Days -and !$TimeSpan.Hours -and !$TimeSpan.Minutes -and !$TimeSpan.Seconds) { $string = '1 Second' }
            $string -replace ', $'
        }

        # Create test user logged in function.
        function Test-UserLoggedIn {
            [CmdletBinding()]
            param(
                [String]$Domain = $env:USERDOMAIN,
                [String]$User = $env:USERNAME
            )
            $explorer = Get-WmiObject -Class 'Win32_Process' -Filter 'Name="explorer.exe"'
            if ($explorer) {
                [bool]($explorer.GetOwner() | Where-Object { $_.Domain -eq $Domain -and $_.User -eq $User })
            } else {
                $false
            }
        }

        # Set version.
        $version = 1

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Set global variables.
        $scriptSuccess = $false
        $scriptError = $false
        $scriptStop = $false
        $scriptDownload = $false
        $scriptInstall = $false
        $autoLoginRemove = $false
        $autoRebootComputer = $false

        # Set computer name.
        $scriptComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()
        $scriptDomain = if ($scriptComputerName -match '\.') {
            ($scriptComputerName -replace '(.*?)\.(.*)','$2').ToLower()
        } else {
            $env:USERDOMAIN.ToLower()
        }

        # Get OS
        $OS = (Get-WmiObject -Class 'Win32_OperatingSystem' -ErrorAction 'SilentlyContinue' | Select-Object -ExpandProperty 'caption' -ErrorAction 'SilentlyContinue') -replace '^Microsoft '

        # Set script variables.
        $scriptName = $command
        $scriptPath = 'C:\' + $scriptName + '.ps1'
        $scriptStart = Get-Date
        $scriptStopFilePath = $env:ProgramData + '\Stop-WindowsUpdate.txt'

        # Set run output variables.
        $runObjectDirectoryPath = $env:ProgramData + '\Scripts\' + $scriptName
        $runObjectFileName = $scriptName + '-' + (Get-Date -Date $scriptStart -Format 'yyyy-MM-ddTHH-mm-ss-ff') + '.xml'
        $runObjectPath = $runObjectDirectoryPath + '\' + $runObjectFileName
        $runObjectSearchPath = $runObjectDirectoryPath + '\' + $scriptName + '-*.xml'

        # Get required Install-WindowsUpdate function.
        $functionInstallWindowsUpdate = Get-Item -Path ('function:\\' + $scriptName)
        $functionInstallWindowsUpdateName = $functionInstallWindowsUpdate.Name
        $functionInstallWindowsUpdateScriptBlock = $functionInstallWindowsUpdate.ScriptBlock
        $functionInstallWindowsUpdateString = 'function ' + $functionInstallWindowsUpdateName + ' {' + $functionInstallWindowsUpdateScriptBlock + '}'

        # Create parameter object.
        $parameterObject = New-Object -TypeName 'psobject'
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'Id' -Value $Id
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'Credential' -Value $Credential.UserName # I can't set this to $Credential because sometimes Import-Clixml will fail with the error: "The requested operation cannot be completed. The computer must be trusted for delegation and the current user account must be configured to allow delegation."
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'AutoReboot' -Value $AutoReboot
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'AutoRun' -Value $AutoRun
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'AutoLogin' -Value $AutoLogin
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'IncludeRecommended' -Value $IncludeRecommended
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'IncludeDriver' -Value $IncludeDriver
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'IncludeHidden' -Value $IncludeHidden
        $parameterObject | Add-Member -MemberType 'NoteProperty' -Name 'VariableName' -Value $VariableName
        
        # Create container object.
        $runObject = New-Object -TypeName 'psobject'
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $scriptComputerName
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Number' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Version' -Value $version
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'FreeSpaceGB' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Domain' -Value $scriptDomain
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'OS' -Value $OS
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value $PSVersionTable.PSVersion
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Parameter' -Value $parameterObject
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'UpdateRetryRun' -Value $false
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'UpdateCount' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Update' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Status' -Value @()
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'StopFile' -Value $false
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'State' -Value 'Running'
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Reboot' -Value $false
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Start' -Value $scriptStart
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'End' -Value ''
        $runObject | Add-Member -MemberType 'NoteProperty' -Name 'Duration' -Value ''

        # Set step.
        $step = 0
        $stepTotal = 9

        # Set check count.
        $checkCount = 0
        $checkCountTotal = 6

        # Create run directory
        if (!(Test-Path -Path $runObjectDirectoryPath)) {
            #Write-Verbose -Message "${command}: Create run object directory."
            New-Item -Path $runObjectDirectoryPath -ItemType 'Directory' -ErrorAction 'Stop' | Out-Null
        }

        # Check stop file.
        if (Test-Path -Path $scriptStopFilePath) {
            $scriptStop = $true
            $runObject.StopFile = $true
            Write-Warning "${command}: Stop file detected! Exiting script."
            #Remove-Item -Path $scriptStopFilePath -Force
            return
        }

        # Step 1: Check the run number.
        # ---------------------------------------------------------------------------------------
        $step = 1
        $checkCount = 1
        $activity = 'Check the run number.'
        Out-Status -Message $activity -Code 1 -Step $step
        $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
        Write-Progress -Activity "Run `#`#: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
        Write-Verbose -Message "${command}: "
        Write-Verbose -Message "${command}: Run `#`#: Check ($checkCount of $checkCountTotal)"
        Write-Verbose -Message "${command}: -----------------------"
        Write-Verbose -Message "${command}: $activity"
        # Set previous run.
        $previousRunObject = ''
        $previousRunObjectCount = 0
        $previousRunObjectPathCount = 0
        # Import previous run objects.
        if ($PSBoundParameters.ContainsKey('Id')) {
            Write-Verbose -Message "${command}: Id is '$Id'."
            Write-Verbose -Message "${command}: Version is '$version'."
            Write-Verbose -Message "${command}: Check for run objects."
            if (Test-Path -Path $runObjectSearchPath -Exclude $runObjectFileName) {
                $previousRunObjectPath = Get-Item -Path $runObjectSearchPath -Exclude $runObjectFileName
                $previousRunObjectPathCount = if ([string]::IsNullOrEmpty($previousRunObjectPath.Count)) { 1 } else { $previousRunObjectPath.Count }
                if ($previousRunObjectPathCount -gt 1) {
                    Write-Verbose -Message "${command}: $previousRunObjectPathCount run objects were found."
                } else {
                    Write-Verbose -Message "${command}: $previousRunObjectPathCount run object was found."
                }
                Write-Verbose -Message "${command}: Check for previous run objects with matching ids and versions."
                $previousRunObjectAll = Import-Clixml -Path $previousRunObjectPath
                $previousRunObject = $previousRunObjectAll | Where-Object { $_.Parameter.Id -eq $Id -and $_.Version -eq $version }
                if ($previousRunObject) {
                    $previousRunObjectCount = if ([string]::IsNullOrEmpty($previousRunObject.Count)) { 1 } else { $previousRunObject.Count }
                    if ($previousRunObjectCount -gt 1) {
                        Write-Verbose -Message "${command}: $previousRunObjectCount run objects with matching ids and versions were found."
                    } else {
                        Write-Verbose -Message "${command}: $previousRunObjectCount run object with matching id and version was found."
                    }
                } else {
                    Write-Verbose -Message "${command}: 0 run objects with matching ids and versions were found."
                }
            } else {
                Write-Verbose -Message "${command}: 0 run objects were found."
            }
        } else {
            Write-Verbose -Message "${command}: No id was provided."
        }
        # Peform reboot run specific activities.
        if ($previousRunObject) {

            # Set number.
            $runNumber = $previousRunObjectCount + 1
            $runObject.Number = $runNumber

            # Write status and verbose.
            $status = "This is run #${runNumber}."
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: This is run #${runNumber}."
        }
        # Peform first run specific activities.
        if (!$previousRunObject) {

            # Set number.
            $runNumber = 1
            $runObject.Number = $runNumber

            # Write status and verbose.
            $status = "This is run #${runNumber}."
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: This is run #${runNumber}."
        }
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed

        # Step 2: Check if sufficient free space is available.
        # ---------------------------------------------------------------------------------------
        $step = 2
        $checkCount = 2
        $activity = 'Check if sufficient free space is available.'
        Out-Status -Message $activity -Code 1 -Step $step
        $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
        Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
        Write-Verbose -Message "${command}: "
        Write-Verbose -Message "${command}: Run #${runNumber}: Check ($checkCount of $checkCountTotal)"
        Write-Verbose -Message "${command}: -----------------------"
        Write-Verbose -Message "${command}: $activity"
        $systemDrive = $env:WinDir -replace '\\.*'
        $freeSpace = Get-WMIObject -Class 'Win32_Logicaldisk' -Filter "deviceid='$systemDrive'" | Select-Object -ExpandProperty 'FreeSpace'
        $freeSpaceGB = [Math]::Round(($freeSpace/1GB),2)
        $runObject.FreeSpaceGB = $freeSpaceGB
        if ($freeSpaceGB -gt 3) {
            $status = "$freeSpaceGB GB. There is sufficent free space available. "
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: $status"
        } else {
            $status = "$freeSpaceGB GB. There is insufficent free space available. "
            Out-Status -Message $status -Code 3 -Step $step
            Write-Error -Message $status -ErrorAction 'Continue'
            return
        }
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed

        # Step 3: Check if the windows update service is enabled.
        # ---------------------------------------------------------------------------------------
        $step = 3
        $checkCount = 3
        $activity = 'Check if the windows update service is enabled.'
        Out-Status -Message $activity -Code 1 -Step $step
        $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
        Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
        Write-Verbose -Message "${command}: "
        Write-Verbose -Message "${command}: Run #${runNumber}: Check ($checkCount of $checkCountTotal)"
        Write-Verbose -Message "${command}: -----------------------"
        Write-Verbose -Message "${command}: $activity"
        if ((Get-Service -Name 'wuauserv').StartType -ne 'Disabled') {
            $status = 'The windows update service is enabled.'
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: $status"
        } else {
            $status = 'The windows update service is disabled.'
            Out-Status -Message $status -Code 3 -Step $step
            Write-Error -Message $status -ErrorAction 'Continue'
            return
        }
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed

        # Step 4: Check if a windows update reboot is required.
        # ---------------------------------------------------------------------------------------
        $step = 4
        $checkCount = 4
        $activity = 'Check if a windows update reboot is required.'
        Out-Status -Message $activity -Code 1 -Step $step
        $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
        Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
        Write-Verbose -Message "${command}: "
        Write-Verbose -Message "${command}: Run #${runNumber}: Check ($checkCount of $checkCountTotal)"
        Write-Verbose -Message "${command}: -----------------------"
        Write-Verbose -Message "${command}: $activity"
        $updateSystemInfo = New-Object -ComObject 'Microsoft.Update.SystemInfo' -ErrorAction 'Stop'
        $updateRebootRequired = $updateSystemInfo.RebootRequired
        if ($updateRebootRequired) {
            #$rebootRequiredCheck = $true
            $runObject.Reboot = $true
            $status = 'A windows update reboot is required.'
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: $status"
        } else {
            #$rebootRequiredCheck = $false
            $status = 'A windows update reboot is not required.'
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: $status"
        }
        Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed

        # Step 5: Check if the windows update installer is busy. Wait if busy.
        # ---------------------------------------------------------------------------------------
        $step = 5
        $checkCount = 5
        $activity = 'Check if the windows update installer is busy.'
        if (!$runObject.Reboot) {

            # Check stop file.
            if (Test-Path -Path $scriptStopFilePath) {
                $scriptStop = $true
                $runObject.StopFile = $true
                Write-Warning "${command}: Stop file detected! Exiting script."
                #Remove-Item -Path $scriptStopFilePath -Force
                return
            }

            # Write status, progress, and verbose.
            Out-Status -Message $activity -Code 1 -Step $step
            $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
            Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
            Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
            Write-Verbose -Message "${command}: "
            Write-Verbose -Message "${command}: Run #${runNumber}: Check ($checkCount of $checkCountTotal)"
            Write-Verbose -Message "${command}: -----------------------"
            Write-Verbose -Message "${command}: $activity"
            
            # Check if the windows update installer is busy.
            $updateInstaller = New-Object -ComObject 'Microsoft.Update.Installer' -ErrorAction 'Stop'

            # If busy, wait until not busy.
            if ($updateInstaller.IsBusy) { # You need to use $updateInstaller.IsBusy to check if it is busy. If you set this to another variable and check it, it won't ever change.
                $status = 'The windows update installer is busy.'
                Out-Status -Message $status -Code 1 -Step $step
                Write-Warning -Message "${command}: $status"
                $startWait = Get-Date
                $status = 'Wait for the windows update installer to become available.'
                Out-Status -Message $status -Code 1 -Step $step
                Write-Warning -Message "${command}: $status"
                While ($updateInstaller.IsBusy) {
                    Start-Sleep -Seconds 1
                    $currentWaitMinutes = [math]::Floor(((Get-Date) - $startWait).TotalMinutes)
                    if ($currentWaitMinutes -ne $previousWaitMinutes) {
                        $previousWaitMinutes = $currentWaitMinutes
                        $status = "The windows update installer is busy. Waited $currentWaitMinutes minutes."
                        Out-Status -Message $status -Code 1 -Step $step
                        Write-Verbose -Message "${command}: $status"
                        
                        # Check stop file.
                        if (Test-Path -Path $scriptStopFilePath) {
                            $scriptStop = $true
                            $runObject.StopFile = $true
                            Write-Warning "${command}: Stop file detected! Exiting script."
                            #Remove-Item -Path $scriptStopFilePath -Force
                            return
                        }
                    } elseif ($currentWaitMinutes -ge 60) {
                        $status = "Wait for the windows update installer to become available timed out after $currentWaitMinutes minutes."
                        Out-Status -Message $status -Code 3 -Step $step
                        Write-Error -Message $status -ErrorAction 'Continue'
                        return
                    }
                }
                $status = 'The windows update installer has become available.'
                Out-Status -Message $status -Code 1 -Step $step
                Write-Warning -Message "${command}: $status"
            } else {
                $status = 'The windows update installer is not busy.'
                Out-Status -Message $status -Code 1 -Step $step
                Write-Verbose -Message "${command}: $status"
            }
            
            # Write progress.
            Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed
        }

        # Step 6: Check if windows updates are available. Create update objects.
        # ---------------------------------------------------------------------------------------
        # Check this link for filter documentation: https://docs.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search
        $step = 6
        $checkCount = 6
        $activity = 'Check if windows updates are available.'
        if (!$runObject.Reboot) {

            # Check stop file.
            if (Test-Path -Path $scriptStopFilePath) {
                $scriptStop = $true
                $runObject.StopFile = $true
                Write-Warning "${command}: Stop file detected! Exiting script."
                #Remove-Item -Path $scriptStopFilePath -Force
                return
            }

            # Write status, progress, and verbose.
            Out-Status -Message $activity -Code 1 -Step $step
            $percentComplete = [Math]::Round(($checkCount/$checkCountTotal)*100,1)
            Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
            Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0
            Write-Verbose -Message "${command}: "
            Write-Verbose -Message "${command}: Run #${runNumber}: Check ($checkCount of $checkCountTotal)"
            Write-Verbose -Message "${command}: -----------------------"
            Write-Verbose -Message "${command}: $activity"

            # Get update search string.
            $updateSearcherString = "IsInstalled=0"
            if ($IncludeDriver) {
                #Write-Verbose -Message "${command}: Include driver updates in search."
            } else {
                $updateSearcherString += " and Type='Software'"
            }
            if ($IncludeRecommended) {
                #Write-Verbose -Message "${command}: Include recommended updates in search."
            } else {
                $updateSearcherString += " and IsAssigned=1"
            }
            if ($IncludeHidden) {
                #Write-Verbose -Message "${command}: Include hidden updates in search."
            } else {
                $updateSearcherString += " and IsHidden=0"
            }

            # Get available windows updates.
            try {
                $updateSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction 'Stop' #### COM ####
                $updateSearcher = $updateSession.CreateUpdateSearcher() #### COM ####
                $updateSearcherUpdate = $updateSearcher.Search("$updateSearcherString").Updates #### COM ####
            } catch {
                Start-Sleep -Seconds 60
                $updateSession = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction 'Stop' #### COM ####
                $updateSearcher = $updateSession.CreateUpdateSearcher() #### COM ####
                $updateSearcherUpdate = $updateSearcher.Search("$updateSearcherString").Updates #### COM ####
            }

            # get available windows updates count.
            $updateSearcherUpdateCount = if ($updateSearcherUpdate) {
                if ([string]::IsNullOrEmpty($updateSearcherUpdate.Count)) { 1 } else { $updateSearcherUpdate.Count }
            } else {
                0
            }
            $runObject.UpdateCount = $updateSearcherUpdateCount

            # Write status and verbose.
            if ($updateSearcherUpdateCount -eq 1) {
                $status = "There is $updateSearcherUpdateCount windows update available."
            } else {
                $status = "There are $updateSearcherUpdateCount windows updates available."
            }
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: $status"
            
            # Create update objects.
            if ($updateSearcherUpdateCount -gt 0) {

                # Set number.
                $number = 0
                $numberTotal = $updateSearcherUpdateCount

                # Create update objects.
                $updateObjects = ForEach($update in $updateSearcherUpdate) {
                
                    # Increment number.
                    $number += 1

                    # Get percent.
                    $percentComplete = [Math]::Round(($number/$numberTotal)*100,1)

                    # Get update properties
                    [String]$title = $update.Title -replace ' \(KB[0-9]+\)$'
                    [Double]$sizeMB  = [math]::Round($update.MaxDownloadSize/1MB,2)
                    [String]$category = $update.Categories | Select-Object -Property 'Name' -First 1 | Select-Object -ExpandProperty 'Name' # Updates, Security Updates, Feature Packs, Critical Updates, Update Rollups
                    [String]$severity = $update.MsrcSeverity # Moderate, Important, Critical
                    [String]$kb = $update.KBArticleIDs # 4493448
                    [String]$bulletin = $update.SecurityBulletinIDs # MS16-120

                    # Create downloadResult object.
                    $downloadResultObject = New-Object -TypeName 'psobject'
                    $downloadResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
                    $downloadResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Description' -Value ''

                    # Create downloadHResult object.
                    $downloadHResultObject = New-Object -TypeName 'psobject'
                    $downloadHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
                    $downloadHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Hexadecimal' -Value ''
                    $downloadHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Message' -Value ''
                    $downloadHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Description' -Value ''
                    $downloadHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Mitigation' -Value ''

                    # Create download object.
                    $downloadObject = New-Object -TypeName 'psobject'
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value $downloadResultObject
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'HResult' -Value $downloadHResultObject
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'State' -Value 'Stopped'
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'Start' -Value ''
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'End' -Value ''
                    $downloadObject | Add-Member -MemberType 'NoteProperty' -Name 'Duration' -Value ''

                    # Create installResult object.
                    $installResultObject = New-Object -TypeName 'psobject'
                    $installResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
                    $installResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Description' -Value ''

                    # Create installHResult object.
                    $installHResultObject = New-Object -TypeName 'psobject'
                    $installHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Code' -Value ''
                    $installHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Hexadecimal' -Value ''
                    $installHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Message' -Value ''
                    $installHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Description' -Value ''
                    $installHResultObject | Add-Member -MemberType 'NoteProperty' -Name 'Mitigation' -Value ''

                    # Create install object.
                    $installObject = New-Object -TypeName 'psobject'
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value $installResultObject
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'HResult' -Value $installHResultObject
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'State' -Value 'Stopped'
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'Start' -Value ''
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'End' -Value ''
                    $installObject | Add-Member -MemberType 'NoteProperty' -Name 'Duration' -Value ''
                
                    # Create update object.
                    $updateObject = New-Object -TypeName 'psobject'
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Title' -Value $title
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Number' -Value $number
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'SizeMB' -Value $sizeMB
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Category' -Value $category
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Severity' -Value $severity
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'KB' -Value $kb
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Bulletin' -Value $bulletin
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Download' -Value $downloadObject
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Install' -Value $installObject
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Percent' -Value $percentComplete
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'State' -Value 'Stopped'
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value ''
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Reboot' -Value $false
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Start' -Value ''
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'End' -Value ''
                    $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Duration' -Value ''

                    # Return object.
                    $updateObject
                }

                # Null update object to prevent it from getting exported to statuses.
                $updateObject = $null # $updateObject = $null just removes the pointer. The object still exists in $updateobjects

                # Write verbose status.
                Write-Verbose -Message "${command}: "
                $consoleWidth = (Get-Host).UI.RawUI.WindowSize.Width - 1
                $exampleWidth = "VERBOSE: ".length
                $lineLengthMax = if ($consoleWidth -is [int]) { $consoleWidth-$exampleWidth } else { 76 }
                $updateObjects | Select-Object @{Name='#';Expression={"$($_.Number))"}},@{Name='size';Expression={"$($_.sizeMB) MB"}},@{Name='Title';Expression={$_.Title}} | Format-Table -AutoSize | Out-String -Stream | ForEach-Object { 
                    $line = "${command}: " + $_.trim()
                    if($line.Length -gt $lineLengthMax) {
                        $line.Substring(0,$line.Length-($line.Length-$lineLengthMax))
                    } elseif ([string]::IsNullOrEmpty($_)) {
                        return
                    } else {
                        $line
                    }
                } | Write-Verbose

                # Save update objects.
                $runObject.Update = $updateObjects
            }
            
            # Write progress.
            Write-Progress -Activity $activity -Status ' ' -PercentComplete 100 -Id 1 -ParentId 0 -Completed
            Write-Progress -Activity "Run #${runNumber}: Check ($checkCount of $checkCountTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0 -Completed
        }

        # Step 7: Download and install windows updates. Perform update retry if required.
        # ---------------------------------------------------------------------------------------
        $step = 7
        $activity = 'Download and install windows updates.'
        if (!$runObject.Reboot -and $updateSearcherUpdateCount -gt 0) {
            
            # Check stop file.
            if (Test-Path -Path $scriptStopFilePath) {
                $scriptStop = $true
                $runObject.StopFile = $true
                Write-Warning "${command}: Stop file detected! Exiting script."
                #Remove-Item -Path $scriptStopFilePath -Force
                return
            }

            # Write status.
            Out-Status -Message $activity -Code 1 -Step $step

            # Set number.
            $number = 0
            $numberTotal = $updateSearcherUpdateCount

            # Download and install windows updates.
            ForEach($update in $updateSearcherUpdate) { 
                
                # Check stop file.
                if (Test-Path -Path $scriptStopFilePath) {
                    $scriptStop = $true
                    $runObject.StopFile = $true
                    Write-Warning "${command}: Stop file detected! Exiting script."
                    #Remove-Item -Path $scriptStopFilePath -Force
                    return
                }

                # Increment number.
                $number += 1

                # Get percent.
                $percentComplete = [Math]::Round(($number/$numberTotal)*100,1)

                # Get update object.
                $updateObject = $updateObjects[$number-1]
                
                # Set update in progress.
                $updateObject.State = 'Running'

                # Get update properties
                $title = $updateObject.Title
                $sizeMB  = $updateObject.sizeMB
                $category = $updateObject.Category
                $severity = $updateObject.Severity
                $kb = $updateObject.KB
                $bulletin = $updateObject.Bulletin

                # Write verbose status.
                Write-Verbose "${command}: "
                Write-Verbose "${command}: Run #${runNumber}: Download & Install ($number of $numberTotal)"
                $consoleWidth = (Get-Host).UI.RawUI.WindowSize.Width - 1
                $exampleWidth = "VERBOSE: ${command}: ".length
                $lineLengthMax = if ($consoleWidth -is [int]) { $consoleWidth-$exampleWidth } else { 87 }
                $line = '-'.PadLeft($lineLengthMax,'-')
                Write-Verbose "${command}: $line"
                $titleLength = $title.Length
                $consoleWidth = (Get-Host).UI.RawUI.WindowSize.Width - 1
                $exampleWidth = "VERBOSE: ${command}: Title    : ".length
                $lineLengthMax = if ($consoleWidth -is [int]) { $consoleWidth-$exampleWidth } else { 76 }
                if ($titleLength -le $lineLengthMax) {
                    Write-Verbose "${command}: Title    : $title"
                } else {
                    $titleLine = @()
                    ForEach($index in 0..[math]::Ceiling($titleLength/$lineLengthMax-1)) {
                        $substringStart = $index*$lineLengthMax
                        $substringLength = if ($titleLength-$substringStart -lt $lineLengthMax) {
                            $titleLength-$substringStart
                        } else {
                            $lineLengthMax
                        }
                        if ($index -eq 0) {
                            Write-Verbose "${command}: Title    : $($title.Substring($substringStart,$substringLength))"
                        } else {
                            Write-Verbose "${command}:          : $($title.Substring($substringStart,$substringLength) -replace '^ ')"
                        }
                    }
                }
                Write-Verbose "${command}: KB       : $kb"
                Write-Verbose "${command}:            -----------------------"

                # Skip previews and language packs.
                if ($title -like '*Preview*' -or $title -like '*Language Pack*') {
                    $updateObject.Percent = $percentComplete
                    $updateObject.Result = 'Skipped'
                    $updateObject.Reboot = $false
                    $updateObject.State = 'Complete'
                    $updateObject.Start = Get-Date
                    $updateObject.End = Get-Date
                    $updateObject.Duration = $updateObject.End - $updateObject.Start
                    Write-Verbose "${command}: Download : Skipped"
                    Write-Verbose "${command}: Install  : Skipped"
                    Write-Verbose "${command}: Reboot   : no"
                    continue
                }

                # Accept eula.
                if ($update.EulaAccepted -eq 0) {
                    $update.AcceptEula() #### COM ####
                } 

                # Create update collection.
                $updateCollection = New-Object -ComObject 'Microsoft.Update.UpdateColl' -ErrorAction 'Stop' #### COM ####
        
                # Add update to collection.
                $updateCollection.Add($update) | Out-Null #### COM ####

                # Download update.
                # ##############################################################
                $status = "Download '$title (KB$kb)' start."
                Out-Status -Message $status -Code 1 -Step $step
                $updateObject.Download.State = 'Running'
                $progressTime = Get-Date -Format 'g'
                Write-Progress -Activity "Run #${runNumber}: Download & Install ($number of $numberTotal)" -Status ' ' -PercentComplete $percentComplete -Id 0
                Write-Progress -Activity "Download: $title" -Status ' ' -CurrentOperation "Start: $progressTime | KB: $kb | Size: $sizeMB MB" -PercentComplete 50 -Id 1 -ParentId 0
                $updateDownloaderStart = Get-Date
                $updateDownloaderStartString = Get-Date -Format 'g'
                Write-Verbose "${command}: Download : Size     > $sizeMB MB"
                Write-Verbose "${command}:          : Start    > $updateDownloaderStartString"
                $updateObject.Download.Start = $updateDownloaderStart
                $updateObject.Start = $updateDownloaderStart
                $updateObject.Percent = $percentComplete
                Export-RunObject # Export everything before the download starts.

                # Download update.
                try {
                    $updateDownloader = $updateSession.CreateUpdateDownloader() #### COM ####
                    if (([System.Environment]::OSVersion.Version.Major -eq 6 -and [System.Environment]::OSVersion.Version.Minor -gt 1) `
                    -or ([System.Environment]::OSVersion.Version.Major -gt 6)) {
                        $updateDownloader.Priority = 4 #### COM #### # 1 (dpLow), 2 (dpNormal), 3 (dpHigh), 4 (dpExtraHigh).
                    } else {
                        # For versions lower then 6.2 highest prioirty is 3
                        $updateDownloader.Priority = 3 #### COM #### # 1 (dpLow), 2 (dpNormal), 3 (dpHigh).
                    }
                    $updateDownloader.Updates = $updateCollection #### COM ####
                    $updateDownloaderResult = $updateDownloader.Download() #### COM ####
                } catch {
                    Start-Sleep -Seconds 10
                    try {
                        $updateDownloader = $updateSession.CreateUpdateDownloader() #### COM ####
                        if (([System.Environment]::OSVersion.Version.Major -eq 6 -and [System.Environment]::OSVersion.Version.Minor -gt 1) `
                        -or ([System.Environment]::OSVersion.Version.Major -gt 6)) {
                            $updateDownloader.Priority = 4 #### COM #### # 1 (dpLow), 2 (dpNormal), 3 (dpHigh), 4 (dpExtraHigh).
                        } else {
                            # For versions lower then 6.2 highest prioirty is 3
                            $updateDownloader.Priority = 3 #### COM #### # 1 (dpLow), 2 (dpNormal), 3 (dpHigh).
                        }
                        $updateDownloader.Updates = $updateCollection #### COM ####
                        $updateDownloaderResult = $updateDownloader.Download() #### COM ####
                    } catch {
                        if ($_.Exception.HResult -is [int]) {
                            $updateInstallerResult = New-Object -TypeName 'psobject'
                            $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'HResult' -Value $_.Exception.HResult
                            $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'ResultCode' -Value 4
                            $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'RebootRequired' -Value $false
                        } else {
                            Write-Error -ErrorRecord $_ -ErrorAction 'Stop'
                        }
                    }
                }

                $updateDownloaderEnd = Get-Date
                $updateDownloaderEndString = Get-Date -Format 'g'
                Write-Verbose "${command}:          : End      > $updateDownloaderEndString"
                $updateObject.Download.End = $updateDownloaderEnd
                $updateDownloaderDuration = $updateDownloaderEnd - $updateDownloaderStart
                $updateDownloaderDurationString = Format-TimeSpanString -TimeSpan $updateDownloaderDuration
                $updateObject.Download.Duration = $updateDownloaderDuration
                Write-Verbose "${command}:          : Duration > $updateDownloaderDurationString"
                $updateDownloaderHResult = Get-WindowsUpdateError -hResult $updateDownloaderResult.HResult
                $updateObject.Download.HResult.Code = $updateDownloaderHResult.Code
                $updateObject.Download.HResult.Hexadecimal = $updateDownloaderHResult.Hexadecimal
                $updateObject.Download.HResult.Message = $updateDownloaderHResult.Message
                $updateObject.Download.HResult.Description = $updateDownloaderHResult.Description
                $updateObject.Download.HResult.Mitigation = $updateDownloaderHResult.Mitigation
                $updateObject.Download.Result.Code = $updateDownloaderResult.ResultCode
                Switch -exact ($updateDownloaderResult.ResultCode) { 
                    0       {$updateDownloaderResultString = 'Not Started' }
                    1       {$updateDownloaderResultString = 'Running' }
                    2       {$updateDownloaderResultString = 'Succeeded' }
                    3       {$updateDownloaderResultString = 'Succeeded With Errors'}
                    4       {$updateDownloaderResultString = 'Failed' }
                    5       {$updateDownloaderResultString = 'Aborted' }
                    default {$updateDownloaderResultString = 'Unknown' }
                }
                Write-Verbose "${command}:          : Result   > $updateDownloaderResultString"
                Write-Verbose "${command}:            -----------------------"
                $updateObject.Download.Result.Description = $updateDownloaderResultString
                $updateObject.Download.State = 'Complete'
                if ($updateObject.Download.Result.Code -eq 2 -and $updateObject.Download.HResult.Code -eq 0) {
                    $updateObject.Install.State = 'Running' # Set here so that when it hits Out-Status below, there will be no lag between the switching download complete and install in progress properties on the export.
                } else {
                    $updateObject.Result = 'Failed' # The overall result is always failed if the install doesn't succeed.
                    $updateObject.End = $updateDownloaderEnd # End is set here because no install is performed.
                    $updateObject.Duration = $updateDownloaderDuration
                    $updateObject.State = 'Complete'
                }

                # Write download status.
                if ($updateDownloaderResultString -eq 'Succeeded') {
                    $status = "Download '$title (KB$kb)' completed with status '$updateDownloaderResultString' in $updateDownloaderDurationString."
                    Out-Status -Message $status -Code 1 -Step $step
                } else {
                    $status = "Download '$title (KB$kb)' completed with status '$updateDownloaderResultString' in $updateDownloaderDurationString."
                    if ($VerbosePreference -ne 'continue') {
                        Write-Warning "${command}: $status"
                    }
                    Out-Status -Message $status -Code 2 -Step $step
                }

                # Set script download.
                $scriptDownload = $true

	            # Install update.
                # ##############################################################
                if ($updateObject.Download.Result.Code -eq 2 -and $updateObject.Download.HResult.Code -eq 0) {

                    $status = "Install '$title (KB$kb)' start."
                    Out-Status -Message $status -Code 1 -Step $step
                    $progressTime = Get-Date -Format 'g'
                    Write-Progress -Activity "Install: $title" -Status ' ' -CurrentOperation "Start: $progressTime | KB: $kb | Size: $sizeMB MB" -PercentComplete 100 -Id 1 -ParentId 0
                    $updateInstallerStart = Get-Date
                    $updateInstallerStartString = Get-Date -Format 'g'
                    Write-Verbose "${command}: Install  : Start    > $updateInstallerStartString"
                    $updateObject.Install.Start = $updateInstallerStart
                    Export-RunObject # Export everything before the install starts.

                    # Install update.
                    try {
                        $updateInstaller = $updateSession.CreateUpdateInstaller() #### COM #### # Exception from HRESULT: 0x80240016
                        $updateInstaller.Updates = $updateCollection #### COM #### # Exception from HRESULT: 0x80240016
                        $updateInstallerResult = $updateInstaller.Install() #### COM #### # Exception from HRESULT: 0x80240016
                    } catch {
                        Start-Sleep -Seconds 10
                        try {
                            $updateInstaller = $updateSession.CreateUpdateInstaller() #### COM #### # Exception from HRESULT: 0x80240016
                            $updateInstaller.Updates = $updateCollection #### COM #### # Exception from HRESULT: 0x80240016
                            $updateInstallerResult = $updateInstaller.Install() #### COM #### # Exception from HRESULT: 0x80240016
                        } catch {
                            if ($_.Exception.HResult -is [int]) {
                                $updateInstallerResult = New-Object -TypeName 'psobject'
                                $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'HResult' -Value $_.Exception.HResult
                                $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'ResultCode' -Value 4
                                $updateInstallerResult | Add-Member -MemberType 'NoteProperty' -Name 'RebootRequired' -Value $false
                            } else {
                                Write-Error -ErrorRecord $_ -ErrorAction 'Stop'
                            }
                        }
                    }

                    $updateInstallerEnd = Get-Date
                    $updateInstallerEndString = Get-Date -Format 'g'
                    Write-Verbose "${command}:          : End      > $updateInstallerEndString"
                    $updateObject.Install.End = $updateInstallerEnd
                    $updateObject.End = $updateInstallerEnd # update 'End' is set here because install is performed.
                    $updateInstallerDuration = $updateInstallerEnd - $updateInstallerStart
                    $updateInstallerDurationString = Format-TimeSpanString -TimeSpan $updateInstallerDuration
                    $updateObject.Install.Duration = $updateInstallerDuration
                    $updateObject.Duration = $updateInstallerEnd - $updateDownloaderStart
                    Write-Verbose "${command}:          : Duration > $updateInstallerDurationString"
                    $updateInstallerHResult = Get-WindowsUpdateError -hResult $updateInstallerResult.HResult
                    $updateObject.Install.HResult.Code = $updateInstallerHResult.Code
                    $updateObject.Install.HResult.Hexadecimal = $updateInstallerHResult.Hexadecimal
                    $updateObject.Install.HResult.Message = $updateInstallerHResult.Message
                    $updateObject.Install.HResult.Description = $updateInstallerHResult.Description
                    $updateObject.Install.HResult.Mitigation = $updateInstallerHResult.Mitigation
                    $updateObject.Install.Result.Code = $updateInstallerResult.ResultCode
                    Switch -exact ($updateInstallerResult.ResultCode) { 
                        0       {$updateInstallerResultString = 'Not Started' }
                        1       {$updateInstallerResultString = 'Running' }
                        2       {$updateInstallerResultString = 'Succeeded' }
                        3       {$updateInstallerResultString = 'Succeeded With Errors' }
                        4       {$updateInstallerResultString = 'Failed' }
                        5       {$updateInstallerResultString = 'Aborted' }
                        default {$updateInstallerResultString = 'Unknown' }
                    }
                    $updateObject.Result = $updateInstallerResultString
                    Write-Verbose "${command}:          : Result   > $updateInstallerResultString"
                    $updateObject.Install.Result.Description = $updateInstallerResultString
                    Write-Progress -Activity "Install: $title" -Status ' ' -CurrentOperation "Start: $progressTime | KB: $kb | Size: $sizeMB MB" -PercentComplete 100 -Id 1 -ParentId 0 -Completed
                    if ($updateInstallerResult.RebootRequired) {
                        Write-Verbose "${command}:          : Reboot   > Yes"
                        $runObject.Reboot = $true
                    } else {
                        Write-Verbose "${command}:          : Reboot   > No"
                    }
                    $updateObject.Reboot = $updateInstallerResult.RebootRequired
                    $updateObject.Install.State = 'Complete'

                    # Set update complete.
                    $updateObject.State = 'Complete'

                    # Write install status.
                    if ($updateInstallerResultString -eq 'Succeeded') {
                        if ($updateInstallerResult.RebootRequired) {
                            $status = "Install '$title (KB$kb)' completed with status '$updateInstallerResultString' in $updateInstallerDurationString. A reboot is required."
                        } else {
                            $status = "Install '$title (KB$kb)' completed with status '$updateInstallerResultString' in $updateInstallerDurationString. A reboot is not required."
                        }
                        Out-Status -Message $status -Code 1 -Step $step
                    } else {
                        $status = "Install '$title' (KB$kb) completed with status '$updateInstallerResultString' in $updateInstallerDurationString."
                        if ($VerbosePreference -ne 'continue') {
                            Write-Warning "${command}: $status"
                        }
                        Out-Status -Message $status -Code 2 -Step $step
                    }

                    # Set script install.
                    $scriptInstall = $true
                }
            }

            # If there were any failed updates that were not installed successfully in subsequent runs, we will perform one extra retry run. 
            if (!$runObject.Reboot -and $Credential -and $AutoReboot -and $AutoRun) {
            
                # Create all run object.
                $allRunObject = @()
                if ($previousRunObject) { $allRunObject += $previousRunObject }
                if ($runObject) { $allRunObject += $runObject }
                if ($allRunObject) { $allRunObject = $allRunObject | Sort-Object -Property 'Number' -ErrorAction 'SilentlyContinue' }

                if ($allRunObject) {
                    
                    # Get failed titles.
                    $allSucceededTitle = $allRunObject.Update | Where-Object { $_.Result -eq 'Succeeded' } | Select-Object -ExpandProperty 'Title' -Unique
                    $allFailedTitle = $allRunObject.Update | Where-Object { $_.Result -eq 'Failed' } | Select-Object -ExpandProperty 'Title' -Unique
                    $failedTitle = $allFailedTitle | ForEach-Object { 
                        if ($allSucceededTitle -notcontains $allFailedTitle) {
                            $_
                        }
                    }

                    # If there was a failed update that never got installed.
                    if ($failedTitle) {

                        # Check if a failed update retry run was previously performed.
                        if ($previousRunObject) {

                            # Get the count of previous retries.
                            $previousFailedRetry = $previousRunObject.UpdateRetryRun | Where-Object { $_ -eq $true }
                            $previousFailedRetryCount = if ($previousFailedRetry) {
                                if ([string]::IsNullOrEmpty($previousFailedRetry.Count)) { 1 } else { $previousFailedRetry.Count }
                            } else {
                                0
                            }

                            # If the count of previous retries is less than the threshold, we'll perform a retry.
                            if ($previousFailedRetryCount -lt 1) {
                                $runObject.UpdateRetryRun = $true
                            }
                        } else {
                            $runObject.UpdateRetryRun = $true
                        }

                        # Set reboot if a failed update retry run will be performed.
                        if ($runObject.UpdateRetryRun) {
                    
                            $runObject.Reboot = $true

                            # Get failed title count.
                            $failedTitleCount = if ($failedTitle) {
                                if ([string]::IsNullOrEmpty($failedTitle.Count)) { 1 } else { $failedTitle.Count }
                            } else {
                                0
                            }

                            # Write status
                            if ($failedTitleCount -eq 1) {
                                $status = "$failedTitleCount update failed to install. A retry run will be performed."
                            } else {
                                $status = "$failedTitleCount updates failed to install. A retry run will be performed."
                            }
                            Out-Status -Message $status -Code 2 -Step $step
                        }
                    }
                }
            }

            # End progress.
            Write-Progress -Activity "Run #${runNumber}: Download & Install ($number of $numberTotal)" -Status ' ' -PercentComplete 100 -Id 0 -Completed
        }

        # Step 8: Perform reboot setup operations.
        # ---------------------------------------------------------------------------------------
        $step = 8
        $activity = 'Perform reboot setup operations.'
        if ($Credential -and $AutoReboot -and $runObject.Reboot) {
            
            # Check stop file.
            if (Test-Path -Path $scriptStopFilePath) {
                $scriptStop = $true
                $runObject.StopFile = $true
                Write-Warning "${command}: Stop file detected! Exiting script."
                #Remove-Item -Path $scriptStopFilePath -Force
                return
            }

            # Write status.
            Out-Status -Message $activity -Code 1 -Step $step

            # Write status.
            Write-Progress -Activity "Restarting..." -Status ' ' -PercentComplete 50 -Id 0
            $status = "The computer will be automatically rebooted."
            Out-Status -Message $status -Code 1 -Step $step
            Write-Verbose -Message "${command}: "
            Write-Verbose -Message "${command}: Run #${runNumber}: Reboot"
            Write-Verbose -Message "${command}: -----------------------"

            # Write verbose.
            if ($AutoReboot) {
                Write-Verbose -Message "${command}: Perform '-AutoReboot' setup actions."
            }
            if ($AutoLogin) {
                Write-Verbose -Message "${command}: Perform '-AutoLogin' setup actions."
            }
            if ($AutoRun) {
                Write-Verbose -Message "${command}: Perform '-AutoRun' setup actions."
            }

            # Get user variables.
            $domain = if ($Credential.UserName -match '\\') { $Credential.UserName -replace '\\.*' } else { $env:USERDOMAIN }
            $user = if ($Credential.UserName -match '\\') { $Credential.UserName -replace '.*\\' } else { $env:USERNAME }
            $password = $Credential.GetNetworkCredential().Password

            # Set auto login.
            if ($AutoLogin) {

                # Get auto login variables.
                $winLogonPath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                $winLogon = Get-ItemProperty -Path $winLogonPath
                $autoAdminLogon = $winLogon.AutoAdminLogon
                $autoLogonCount = $winLogon.AutoLogonCount
                $defaultDomainName = $winLogon.DefaultDomainName
                $defaultUserName = $winLogon.DefaultUserName
                $defaultPassword = $winLogon.DefaultPassword

                # Check if auto login is already set. If so, the script will persist it.
                if ($autoAdminLogon -ne 1) {
                    Write-Verbose -Message "${command}: Auto login is not currently set."
                    Write-Verbose -Message "${command}: Auto login will be removed after reboot."
                    $autoLoginRemove = $true
                } else {
                    Write-Verbose -Message "${command}: Auto login is currently set."
                    Write-Verbose -Message "${command}: Auto login will be persisted after reboot."
                    $autoLoginRemove = $false
                }

                # Set auto login.
                if ($autoAdminLogon -ne 1) {
                    Write-Verbose -Message "${command}: Set 'AutoAdminLogon' to '1'."
                    New-ItemProperty -Path $winLogonPath -Name 'AutoAdminLogon' -Value '1' -PropertyType 'String' -Force | Out-Null
                }
                if ($autoLogonCount -ne $null) {
                    Write-Verbose -Message "${command}: Remove 'AutoLogonCount'."
                    Remove-ItemProperty -Path $winLogonPath -Name 'AutoLogonCount' -Force | Out-Null
                }
                if ($defaultDomainName -ne $domain) {
                    Write-Verbose -Message "${command}: Set 'DefaultDomainName' to '$domain'."
                    New-ItemProperty -Path $winLogonPath -Name 'DefaultDomainName' -Value $domain -PropertyType 'String' -Force | Out-Null
                }
                if ($defaultUserName -ne $user) {
                    Write-Verbose -Message "${command}: Set 'DefaultUserName' to '$user'."
                    New-ItemProperty -Path $winLogonPath -Name 'DefaultUserName' -Value $user -PropertyType 'String' -Force | Out-Null
                }
                if ($defaultPassword -ne $password) {
                    Write-Verbose -Message "${command}: Set 'DefaultPassword' to '$password'."
                    New-ItemProperty -Path $winLogonPath -Name 'DefaultPassword' -Value $password -PropertyType 'String' -Force | Out-Null
                }
            }

            # Create the scheduled task.
            if ($AutoLogin) {

                # Interactive session.
                if ([Environment]::GetCommandLineArgs() -contains '-NoExit') {
                    Write-Verbose -Message "${command}: Generate onlogon scheduled task '$scriptName'."
                    schtasks /create /tn "$scriptName" /ru "$domain\$User" /sc "onlogon" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoExit -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                } else {
                    Write-Verbose -Message "${command}: Generate onlogon scheduled task '$scriptName'."
                    schtasks /create /tn "$scriptName" /ru "$domain\$User" /sc "onlogon" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
                }

            } else {

                # Non-Interactive session.
                Write-Verbose -Message "${command}: Generate onstart scheduled task '$scriptName'."
                schtasks /create /tn "$scriptName" /ru "$domain\$User" /rp "$Password" /sc "onstart" /rl "highest" /f /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File ""$scriptPath""" | Out-Null
            
            }

            # Build the script.
            Write-Verbose -Message "${command}: Generate restart script '$scriptPath'."
            $script = ''
            
            # Set verbose.
            if ($VerbosePreference -eq 'continue') {
                $script += "`r`n" +
@'
# Set verbose
########################################################
$VerbosePreference = 'continue'
'@ + "`r`n"
            }

            # Remove script.
            $script += "`r`n" +
@"
# Remove script
########################################################
Write-Verbose "Remove script '$scriptPath'."
Remove-Item -Path '$scriptPath' -Force
"@ + "`r`n"
            
            # Remove scheduled task.
            $script += "`r`n" +
@"
# Remove scheduled task
########################################################
Write-Verbose "Remove scheduled task '$scriptName'."
schtasks /delete /tn "$scriptName" /f | Out-Null
"@ + "`r`n"
            
            # Remove auto login.
            if ($autoLoginRemove) {

                $script += "`r`n" +
@'
# Remove auto login
########################################################
Write-Verbose "Remove auto login."
$winLogonPath = 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$winLogon = Get-ItemProperty -Path $winLogonPath
$autoAdminLogon = $winLogon.AutoAdminLogon
$defaultPassword = $winLogon.DefaultPassword
if ($autoAdminLogon -ne $null) {
    Remove-ItemProperty -Path $winLogonPath -Name 'AutoAdminLogon' -Force | Out-Null
}
if ($defaultPassword -ne $null) {
    Remove-ItemProperty -Path $winLogonPath -Name 'DefaultPassword' -Force | Out-Null
}
'@ + "`r`n"
            }

            # Automatically rerun the script after restart.
            if ($AutoRun) {
                
                # Wait.
                $script += "`r`n" +
@'
# Wait
########################################################
$secondsToWait = 20
Write-Verbose "Wait $secondsToWait seconds."
Write-Progress -Activity "Waiting $secondsToWait seconds: (0 of $secondsToWait complete)" -Status ' ' -PercentComplete 0 -Id 0
For($Index = 1; $Index -le $secondsToWait; $Index += 1)
{
    Start-Sleep -Seconds 1
    $PercentComplete = [Math]::Round(($Index/$secondsToWait)*100,1)
    Write-Progress -Activity "Waiting $secondsToWait seconds: ($Index of $secondsToWait complete)" -Status ' ' -PercentComplete $PercentComplete -Id 0
}
Write-Progress -Activity "Waiting $secondsToWait seconds: ($secondsToWait of $secondsToWait complete)" -Status ' ' -PercentComplete 100 -Id 0 -Completed
'@ + "`r`n"
                
                # Import the function.
                $script += "`r`n"
                $script += '# Import Install-WindowsUpdate function' + "`r`n"
                $script += '########################################################' + "`r`n"
                $script += '$functionInstallWindowsUpdateString = {' + "`r`n"
                $script += $functionInstallWindowsUpdateString
                $script += '}.ToString()' + "`r`n"
                $script += 'Invoke-Expression -Command $functionInstallWindowsUpdateString' + "`r`n"

                # Get parameters.
                $script += "`r`n"
                $script += '# Get parameters' + "`r`n"
                $script += '########################################################' + "`r`n"
                $script += '$param = @{}' + "`r`n"
                if ($Credential) {
                    $script += '$param.Credential = New-Object -TypeName ''System.Management.Automation.PSCredential'' -ArgumentList @(''' + $domain + '\' + $user + ''',(ConvertTo-SecureString -String ''' + $password + ''' -AsPlainText -Force))' + "`r`n"
                }
                if ($AutoReboot) {
                    $script += '$param.AutoReboot = $true' + "`r`n"
                }
                if ($AutoRun) {
                    $script += '$param.AutoRun = $true' + "`r`n"
                }
                if ($AutoLogin) {
                    $script += '$param.AutoLogin = $true' + "`r`n"
                }
                if ($IncludeRecommended) {
                    $script += '$param.IncludeRecommended = $true' + "`r`n"
                }
                if ($IncludeDriver) {
                    $script += '$param.IncludeDriver = $true' + "`r`n"
                }
                if ($IncludeHidden) {
                    $script += '$param.IncludeHidden = $true' + "`r`n"
                }
                if ($Id) {
                    $script += '$param.Id = ''' + $Id + '''' + "`r`n"
                }
                if ($VariableName) {
                    $script += '$param.VariableName = ''' + $VariableName + '''' + "`r`n"
                }
                
                # Run the function.
                $script += "`r`n"
                $script += '# Run Install-WindowsUpdate function' + "`r`n"
                $script += '########################################################' + "`r`n"
                $script += '$' + $VariableName + ' = ' + "$functionInstallWindowsUpdateName @param" + "`r`n"
            }

            # Output the script.
            $script -replace "(?<!`r)`n","`r`n" | Out-File -FilePath $scriptPath -Width 4096 -Force

            # Set auto reboot computer.
            $autoRebootComputer = $true
        }
        
        # Set script success.
        $scriptSuccess = $true

    } catch {

        # Remove restart script and scheduled task in case they leftover for some reason.
        schtasks /delete /tn $scriptName /f > $null 2>&1
        schtasks /delete /tn "Start-WindowsUpdate" /f > $null 2>&1
        Remove-Item -Path $scriptPath -Force -ErrorAction 'SilentlyContinue'

        # Write error message.
        $status = $_.Exception.Message -replace "^${command}: "
        Write-Warning -Message "${command}: "
        Write-Warning -Message "${command}: Run #${runNumber}: !!! ERROR !!!"
        Write-Warning -Message "${command}: -----------------------"
        Write-Warning -Message "${command}: $status"
        if ($runObject) {
            Out-Status -Message $status -Code 3 -Step $step
        }

        # Set script error.
        $scriptError = $true

    } finally {
        
        # Remove old previous run objects ($previousRunObjectPath comes from the import section).
        if ($previousRunObjectPath) {
            Write-Verbose -Message "${command}: Check for old run objects."
            $previousRunObjectPathOld = $previousRunObjectPath | Where-Object { ((Get-Date)-$_.CreationTime).TotalDays -gt 30 }
            if ($previousRunObjectPathOld) {
                Write-Verbose -Message "${command}: "
                Write-Verbose -Message "${command}: Cleanup"
                Write-Verbose -Message "${command}: -----------------------"
                Remove-Item -Path $previousRunObjectPathOld -Force
                $previousRunObjectPathOldCount = if ([string]::IsNullOrEmpty($previousRunObjectPathOld.Count)) { 1 } else { $previousRunObjectPathOld.Count }
                if ($previousRunObjectPathOldCount -gt 1) {
                    Write-Verbose -Message "${command}: $previousRunObjectPathOldCount old run objects were removed."
                } else {
                    Write-Verbose -Message "${command}: $previousRunObjectPathOldCount old run object was removed."
                }
            } else {
                Write-Verbose -Message "${command}: 0 old run objects were found."
            }
        }

        # Step 9: Script complete.
        # ---------------------------------------------------------------------------------------
        $step = 9
        $activity = 'Script complete.'

        # Get script duration.
        $scriptEnd = Get-Date
        $scriptDuration = $scriptEnd - $scriptStart

        # Check stop file.
        if (!$scriptStop -and (Test-Path -Path $scriptStopFilePath)) {
            $scriptStop = $true
            $runObject.StopFile = $true
            Write-Warning "${command}: Stop file detected! Exiting script."
            #Remove-Item -Path $scriptStopFilePath -Force
        }

        # Populate run object final values and export run object for the last time.
        if ($runObject) {
            
            # Populate run object final values.
            $runObject.End = $scriptEnd
            $runObject.Duration = $scriptDuration
            $runObject.State = 'Complete'
            $runObject.Result = if ($scriptError) { 'Failed' } else { 'Succeeded' }

            # Export run object.
            if ($autoRebootComputer) {
                if ($scriptSuccess) {
                    if ($AutoRun) {
                        $status = "Run #${runNumber} complete. Auto reboot and auto run."
                    } else {
                        $status = "Script complete. Auto reboot."
                    }
                }
            } else {
                if ($runObject.Reboot) {
                    $status = "Script complete. A manual reboot is required."
                } else {
                    $status = "Script complete."
                }
            }
            Out-Status -Message $status -Code 1 -Step $step
        }

        # --------------------- Anything after this will not be exported ---------------------

        # Create return run object.
        $returnRunObject = @()
        if ($previousRunObject) { $returnRunObject += $previousRunObject }
        if ($runObject) { $returnRunObject += $runObject }
        if ($returnRunObject) { $returnRunObject = $returnRunObject | Sort-Object -Property 'Number' -ErrorAction 'SilentlyContinue' }

        # Write verbose.
        Write-Verbose -Message "${command}: "
        Write-Verbose -Message "${command}: Run #${runNumber}: Complete"
        if ($returnRunObject) {
            
            # Get individual run duration, end, update succeeded count, and update failed count.
            ForEach($item in $returnRunObject) {
                
                # Write verbose duration and end.
                Write-Verbose -Message "${command}: -----------------------"
                if ($item.Duration) {
                    Write-Verbose -Message "${command}: Run #$($item.Number): Completed in $(Format-TimeSpanString -TimeSpan $item.Duration)."
                }
                if ($item.End) {
                    Write-Verbose -Message "${command}: Run #$($item.Number): Completed on $(Get-Date -Date $item.End -Format 'g')."
                }

                # Get update succeeded count.
                $runUpdateSucceeded = $item.Update | Where-Object { $_.Result -eq 'Succeeded' }
                $runUpdateSucceededCount = if ($runUpdateSucceeded) {
                    if ([string]::IsNullOrEmpty($runUpdateSucceeded.Count)) { 1 } else { $runUpdateSucceeded.Count }
                } else {
                    0
                }
                    
                # Write verbose update succeeded count.
                if ($runUpdateSucceededCount -eq 1) {
                    Write-Verbose -Message "${command}: Run #$($item.Number): Installed $runUpdateSucceededCount update."
                } else {
                    Write-Verbose -Message "${command}: Run #$($item.Number): Installed $runUpdateSucceededCount updates."
                }

                # Get and write verbose update failed count.
                $runUpdateFailed = $item.Update | Where-Object { $_.Result -eq 'Failed' }
                if ($runUpdateFailed) {
                    
                    # Get update failed count.
                    $runUpdateFailedCount = if ($runUpdateFailed) {
                        if ([string]::IsNullOrEmpty($runUpdateFailed.Count)) { 1 } else { $runUpdateFailed.Count }
                    } else {
                        0
                    }
                    
                    # Write verbose update failed count.
                    if ($runUpdateFailedCount -eq 1) {
                        Write-Verbose -Message "${command}: Run #$($item.Number): Failed $runUpdateFailedCount update."
                    } else {
                        Write-Verbose -Message "${command}: Run #$($item.Number): Failed $runUpdateFailedCount updates."
                    }
                }
            }

            # Get total run duration, end, succeeded, and failed update count.
            if ($previousRunObject) {

                # Get total run duration, succeeded, and failed update count.
                $firstRunStart = $previousRunObject | Where-Object { $_.Number -eq 1 } | Select-Object -ExpandProperty 'Start'
                
                if ($firstRunStart) {
                    
                    # Get total run duration.
                    $totalRunDuration = $scriptEnd - $firstRunStart
                    Write-Verbose -Message "${command}: -----------------------"
                    Write-Verbose -Message "${command}: Total: Completed in $(Format-TimeSpanString -TimeSpan $totalRunDuration)."
                    Write-Verbose -Message "${command}: Total: Completed on $(Get-Date -Date $scriptEnd -Format 'g')."

                    # Get update succeeded count.
                    $totalrunUpdateSucceeded = $returnRunObject.Update | Where-Object { $_.Result -eq 'Succeeded' }
                    $totalrunUpdateSucceededCount = if ($totalrunUpdateSucceeded) {
                        if ([string]::IsNullOrEmpty($totalrunUpdateSucceeded.Count)) { 1 } else { $totalrunUpdateSucceeded.Count }
                    } else {
                        0
                    }
                        
                    # Write verbose update succeeded count.
                    if ($totalrunUpdateSucceededCount -eq 1) {
                        Write-Verbose -Message "${command}: Total: Installed $totalrunUpdateSucceededCount update."
                    } else {
                        Write-Verbose -Message "${command}: Total: Installed $totalrunUpdateSucceededCount updates."
                    }

                    # Get total run update failed count.
                    if ($returnRunObject.Update) {
                
                        # Get failed titles.
                        $allSucceededTitle = $returnRunObject.Update | Where-Object { $_.Result -eq 'Succeeded' } | Select-Object -ExpandProperty 'Title' -Unique
                        $allFailedTitle = $returnRunObject.Update | Where-Object { $_.Result -eq 'Failed' } | Select-Object -ExpandProperty 'Title' -Unique
                        $failedTitle = $allFailedTitle | ForEach-Object { 
                            if ($allSucceededTitle -notcontains $allFailedTitle) {
                                $_
                            }
                        }

                        if ($failedTitle) {

                            # Get update failed count.
                            $failedTitleCount = if ($failedTitle) {
                                if ([string]::IsNullOrEmpty($failedTitle.Count)) { 1 } else { $failedTitle.Count }
                            } else {
                                0
                            }
                            
                            # Write verbose update failed count.
                            if ($failedTitleCount -eq 1) {
                                Write-Verbose -Message "${command}: Total: Failed $failedTitleCount update."
                            } else {
                                Write-Verbose -Message "${command}: Total: Failed $failedTitleCount updates."
                            }
                        }
                    }
                }
            }
        } else {
            Write-Verbose -Message "${command}: -----------------------"
        }

        # Do script success operations.
        if ($autoRebootComputer) {

            # Reboot the computer.
            if ($scriptSuccess -and !$scriptStop) {
                Write-Progress -Activity "Rebooting..." -Status ' ' -PercentComplete 100 -Id 0 -Completed
                Write-Verbose -Message "${command}: Automatic reboot initiated."
                Restart-Computer -Force
            }

        } else {
            
            # Return run objects.
            if ($returnRunObject) {
                $returnRunObject
            }

            # Reboot the computer?
            if ($scriptSuccess -and !$scriptStop -and $runObject.Reboot -and [Environment]::UserInteractive) {
                $rebootComputerResponse = Read-Host -Prompt "A reboot is required. Would you like to reboot now? Y/N"
                if ($rebootComputerResponse -eq 'yes' -or $rebootComputerResponse -eq 'y') {
                    Write-Verbose -Message "${command}: Reboot initiated."
                    Restart-Computer -Force
                }
            }
        }
    }
}

Function Get-WindowsUpdate {
    <#
    .SYNOPSIS
        The Get-WindowsUpdate function queries windows updates available on a remote system. The "update" objects are returned in a container for convenience (See outputs below).
		
	.DESCRIPTION
		The Get-WindowsUpdate function queries windows updates available on a remote system. The "update" objects are returned in a container for convenience (See outputs below).
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER IncludeRecommended
        Forces recommended (optional) updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeDriver
        Forces driver updates to be installed. By default, only important updates are installed.
		
    .PARAMETER IncludeHidden
        Forces hidden updates to be installed. By default, only important updates are installed.
	
	.PARAMETER Timeout
		...
	
	.PARAMETER AsJob
		Runs the function as a job.
		
	.OUTPUTS
        Returns an "update" object container containing:
        -------------------------------------------------------------------------------
        #            : Just a counter for convience.
        ComputerName : The computer name or IP address.
        Result       : Contains "Succeeded" if the Get-WindowsUpdate function successfully queried for Windows updates. Contains "Failed" if there was an error or the function timed out.
        UpdateCount  : The number of update objects.
        Update       : Update objects.
        -------------------------------------------------------------------------------
		
	.EXAMPLE
		Get-WindowsUpdate -ComputerName $computerName -Credential $credential
		
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [Switch]
        $IncludeRecommended,

        [Parameter()]
        [Switch]
        $IncludeDriver,

        [Parameter()]
        [Switch]
        $IncludeHidden,

        [Parameter()]
        [Int]
        $Timeout = 600,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get update object containers.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
            $IncludeRecommended
            $IncludeDriver
            $IncludeHidden
            $Timeout
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            $IncludeRecommended = $args[5]
            $IncludeDriver = $args[6]
            $IncludeHidden = $args[7]
            $Timeout = $args[8]

            # Get computer names online.
            $computerNameOnline = @(
                if ($ComputerName) {
                    ForEach ($computer in $ComputerName) {
                        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                            $computer
                        } else {
                            Write-Warning "${command}: $computer ping failed."
                        }
                    }
                }
            )

            # Get sessions online.
            $sessionOnline = @(
                if ($Session) {
                    ForEach ($sess in $Session) {
                        if ($sess.State -eq 'Opened' -and $sess.Availability -eq 'Available' -and (Test-Connection -ComputerName $sess.ComputerName -Count 1 -Quiet)) {
                            $sess
                        } else {
                            Write-Warning "${command}: $($sess.ComputerName) ping failed."
                        }
                    }
                }
            )
        
            # Get update object containers.
            $updateObjectContainers = if ($computerNameOnline -or $sessionOnline) {

                # Get update object containers.
                $param = @{}
                if ($computerNameOnline) {
                    $param.ComputerName = $computerNameOnline
                    $param.Credential = $Credential
                    $param.SessionOption = New-PSSessionOption -NoMachineProfile
                }
                if ($sessionOnline) {
                    $param.Session = $sessionOnline
                }
                $param.ThrottleLimit = 200
                $param.ArgumentList = @(
                    $VerbosePreference
                    $command
                    $IncludeRecommended
                    $IncludeDriver
                    $IncludeHidden
                    $Timeout
                )
                $param.ScriptBlock = {
					
                    # Set variables.
                    $VerbosePreference = $args[0]
                    $command = $args[1]
                    $IncludeRecommended = $args[2]
                    $IncludeDriver = $args[3]
                    $IncludeHidden = $args[4]
                    $Timeout = $args[5]

                    try {

                        # Set environment variables.
                        $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                        # Write verbose.
                        Write-Verbose -Message "${command}: $envComputerName."

                        # Create update object container.
                        $updateObjectContainer = New-Object -TypeName 'psobject'
                        $updateObjectContainer | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                        $updateObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                        $updateObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value ''
                        $updateObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'UpdateCount' -Value ''
                        $updateObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'Update' -Value ''

                        # Get update objects.
                        try {
                            $param = @{
                                ArgumentList = @(
                                    $VerbosePreference
                                    $command
                                    $IncludeRecommended
                                    $IncludeDriver
                                    $IncludeHidden
                                )
                                ScriptBlock = {
									
                                    # Set variables.
                                    $VerbosePreference = $args[0]
                                    $command = $args[1]
                                    $IncludeRecommended = $args[2]
                                    $IncludeDriver = $args[3]
                                    $IncludeHidden = $args[4]

                                    # Get windows updates.
                                    $updateSearcher = New-Object -ComObject 'Microsoft.Update.Searcher' -ErrorAction 'Stop'
                                    $updateSearcherString = "IsInstalled=0"
                                    if ($IncludeDriver) {
                                        # Write-Verbose -Message "${command}: Include driver updates in search."
                                    } else {
                                        $updateSearcherString += " and Type='Software'"
                                    }
                                    if ($IncludeRecommended) {
                                        # Write-Verbose -Message "${command}: Include recommended updates in search."
                                    } else {
                                        $updateSearcherString += " and IsAssigned=1"
                                    }
                                    if ($IncludeHidden) {
                                        # Write-Verbose -Message "${command}: Include hidden updates in search."
                                    } else {
                                        $updateSearcherString += " and IsHidden=0"
                                    }
                                    $updateSearcherUpdate = $updateSearcher.Search("$updateSearcherString").Updates
                                
                                    # Get windows update count.
                                    if ($updateSearcherUpdate) {
                                        $updateSearcherUpdateCount = if ([string]::IsNullOrEmpty($updateSearcherUpdate.Count)) { 1 } else { $updateSearcherUpdate.Count }
                                    } else {
                                        $updateSearcherUpdateCount = 0
                                    }
                    
                                    # Get update objects.
                                    $updateObjects = if ($updateSearcherUpdateCount -gt 0) {

                                        # Set number.
                                        $number = 0
                                        $numberTotal = $updateSearcherUpdateCount

                                        # Get update objects.
                                        ForEach($update in $updateSearcherUpdate) {
                                        
                                            # Increment number.
                                            $number += 1

                                            # Get update properties
                                            [String]$title = $update.Title -replace ' \(KB[0-9]+\)$'
                                            [Double]$sizeMB  = [math]::Round($update.MaxDownloadSize/1MB,2)
                                            [String]$category = $update.Categories | Select-Object -Property 'Name' -First 1 | Select-Object -ExpandProperty 'Name' # Updates, Security Updates, Feature Packs, Critical Updates, Update Rollups
                                            [String]$severity = $update.MsrcSeverity # Moderate, Important, Critical
                                            [String]$kb = $update.KBArticleIDs # 4493448
                                            [String]$bulletin = $update.SecurityBulletinIDs # MS16-120

                                            # Create update object.
                                            $updateObject = New-Object -TypeName 'psobject'
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Title' -Value $title
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Number' -Value $number
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'SizeMB' -Value $sizeMB
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Category' -Value $category
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Severity' -Value $severity
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'KB' -Value $kb
                                            $updateObject | Add-Member -MemberType 'NoteProperty' -Name 'Bulletin' -Value $bulletin

                                            # Return update object.
                                            $updateObject
                                        }
                                    }

                                    # Return update objects.
                                    $updateObjects
                                }
                            }
                            $job = Start-Job @param
                            $jobComplete = Wait-Job -Job $job -Timeout $Timeout -ErrorAction 'Stop' # Wait-Job does not return any jobs on timeout.
                            $updateObjects = if ($jobComplete) {
                                $updateObjects = Receive-Job -Job $jobComplete -ErrorAction 'Stop'
                                $updateObjects = $updateObjects | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'
                                $updateObjects
                            }

                            # Set result.
                            $updateObjectContainer.Result = if ($jobComplete) {
                                'Succeeded'
                            } else {
                                'Failed'
                            }

                        } catch {
                            
                            # Set result.
                            $updateObjectContainer.Result = 'Failed'

                            # Write error.
                            Write-Error -ErrorRecord $_

                        }
                    
                        # Set update.
                        $updateObjectContainer.Update = $updateObjects

                        # Set update count.
                        $updateObjectContainer.UpdateCount = if ($updateObjectContainer.Update) {
                            if ([string]::IsNullOrEmpty($updateObjectContainer.Update.Count)) { 1 } else { $updateObjectContainer.Update.Count }
                        } else {
                            0
                        }

                        # Return update object container.
                        $updateObjectContainer

                    } catch {
                        
                        # Write error.
                        Write-Error -ErrorRecord $_

                    } finally {
                    
                        # Remove job.
                        if ($job) {
                            Remove-Job -Job $job -Force -ErrorAction 'SilentlyContinue'
                        }
                    }
                }
                try {
                    Invoke-Command @param
                } catch {
                    Write-Warning "${command}: $($_.TargetObject) session failed."
                }
            }

            # Return update object containers.
            if ($updateObjectContainers) {
            
                # Add ComputerName to update object containers.
                $count = 0
                ForEach($updateObjectContainer in $updateObjectContainers) {
                    $updateObjectContainer.ComputerName = $updateObjectContainers[$count].PSComputerName
                    $count += 1
                }

                # Sort update object containers.
                $updateObjectContainers = $updateObjectContainers | Sort-Object -Property 'ComputerName'
            
                # Add # to update object containers.
                $count = 1
                ForEach($updateObjectContainer in $updateObjectContainers) {
                    $updateObjectContainer.'#' = $count
                    $count += 1
                }

                # Exclude pscomputername, psshowcomputername, and runspaceid.
                $updateObjectContainers = $updateObjectContainers | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                # Return update object containers.
                $updateObjectContainers
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Get-WindowsUpdateRun {
    <#
    .SYNOPSIS
        The Get-WindowsUpdateRun function gets outputted Install-WindowsUpdate "run" objects by reading the run xml files generated by the Install-WindowsUpdate function. The "run" objects are returned in a containter for convenience (See outputs below).
		
	.DESCRIPTION
        The Get-WindowsUpdateRun function gets outputted Install-WindowsUpdate "run" objects by reading the run xml files generated by the Install-WindowsUpdate function. The "run" objects are returned in a containter for convenience (See outputs below).
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER Id
        A variable used to group runs and query status information about them.
		
    .PARAMETER Version
        Currently not used. Could be used in the future to version the "run" objects if there are breaking changes to the formatting.
		
    .PARAMETER AsJob
        Runs the function as a job.
		
    .OUTPUTS
        Returns a "run" object container containing:
        -------------------------------------------------------------------------------
        #            : Just a counter for convience.
        ComputerName : The computer name or IP address.
        RunCount     : The number of run objects.
        Run          : Run objects.
        -------------------------------------------------------------------------------
		
	.EXAMPLE
		Get-WindowsUpdateRun -ComputerName $computerName -Credential $credential -Id $id
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Version,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get run object containers online.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
            $Id
            $Version
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            $Id = $args[5]
            $Version = $args[6]

            # Get computer names online.
            $computerNameOnline = @(
                if ($ComputerName) {
                    ForEach ($computer in $ComputerName) {
                        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                            $computer
                        } else {
                            Write-Warning "${command}: $computer ping failed."
                        }
                    }
                }
            )

            # Get sessions online.
            $sessionOnline = @(
                if ($Session) {
                    ForEach ($sess in $Session) {
                        if ($sess.State -eq 'Opened' -and $sess.Availability -eq 'Available' -and (Test-Connection -ComputerName $sess.ComputerName -Count 1 -Quiet)) {
                            $sess
                        } else {
                            Write-Warning "${command}: $($sess.ComputerName) ping failed."
                        }
                    }
                }
            )

            # Get run object containers online.
            $runObjectContainers = if ($computerNameOnline -or $sessionOnline) {

                # Get run object containers.
                $param = @{}
                if ($computerNameOnline) {
                    $param.ComputerName = $computerNameOnline
                    $param.Credential = $Credential
                    $param.SessionOption = New-PSSessionOption -NoMachineProfile
                }
                if ($sessionOnline) {
                    $param.Session = $sessionOnline
                }
                $param.ThrottleLimit = 200
                $param.ErrorAction = 'Stop'
                $param.ArgumentList = @(
                    $VerbosePreference
                    $command
                    $Id
                    $Version
                )
                $param.ScriptBlock = {
                    
                    # Set variables.
                    $VerbosePreference = $args[0]
                    $command = $args[1]
                    $Id = $args[2]
                    $Version = $args[3]

                    try {

                        # Set environment variables.
                        $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                        # Write verbose.
                        Write-Verbose -Message "${command}: $envComputerName."

                        # Create run object container.
                        $runObjectContainer = New-Object -TypeName 'psobject'
                        $runObjectContainer | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                        $runObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                        $runObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'RunCount' -Value ''
                        $runObjectContainer | Add-Member -MemberType 'NoteProperty' -Name 'Run' -Value ''

                        # Set run.
                        $runObjectSearchPath = $env:ProgramData + '\Scripts\Install-WindowsUpdate\Install-WindowsUpdate-*.xml'
                        $runObjectContainer.Run = if (Test-Path -Path $runObjectSearchPath) {
                            $runObjectPath = Get-Item -Path $runObjectSearchPath -ErrorAction 'SilentlyContinue'
                            try {
                                $runObjectAll = Import-Clixml -Path $runObjectPath -ErrorAction 'Stop'
                                if ($runObjectAll) {
                                    if ($Id -or $Version) {
                                        if ($Id -and $Version) {
                                            $runObject = $runObjectAll | Where-Object { $_.Parameter.Id -eq $Id -and $_.Version -eq $Version }
                                        } elseif ($Id) {
                                            $runObject = $runObjectAll | Where-Object { $_.Parameter.Id -eq $Id }
                                        } elseif ($Version) {
                                            $runObject = $runObjectAll | Where-Object { $_.Version -eq $Version }
                                        }
                                        if ($runObject) {
                                            $runObject = $runObject | Sort-Object -Property 'Number'
                                            $runObject
                                        } else {
                                            Write-Warning -Message "${command}: $envComputerName has no run objects matching the search criteria."
                                        }
                                    } else {
                                        $runObjectAll
                                    }
                                }
                            } catch {
                                Write-Warning -Message "${command}: $envComputerName has run objects that could not be read."
                            }
                        } else {
                            Write-Warning -Message "${command}: $envComputerName has no run objects."
                        }

                        # Set run count.
                        $runObjectContainer.RunCount = if ($runObjectContainer.Run) { 
                            if ([string]::IsNullOrEmpty($runObjectContainer.Run.Count)) { 1 } else { $runObjectContainer.Run.Count }
                        } else {
                            0
                        }

                        # Return run object container.
                        $runObjectContainer

                    } catch {

                        # Write error.
                        Write-Error -ErrorRecord $_

                    }
                }
                try {
                    Invoke-Command @param
                } catch {
                    Write-Warning "${command}: $($_.TargetObject) session failed."
                }
            }

            # Return run object containers.
            if ($runObjectContainers) {

                # Add ComputerName to run object containers.
                $count = 0
                ForEach($runObjectContainer in $runObjectContainers) {
                    $runObjectContainer.ComputerName = $runObjectContainers[$count].PSComputerName
                    $count += 1
                }

                # Sort run object containers.
                $runObjectContainers = $runObjectContainers | Sort-Object -Property 'ComputerName'
            
                # Add # to run object containers.
                $count = 1
                ForEach($runObjectContainer in $runObjectContainers) {
                    $runObjectContainer.'#' = $count
                    $count += 1
                }

                # Exclude pscomputername, psshowcomputername, and runspaceid.
                $runObjectContainers = $runObjectContainers | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                # Return run object containers.
                $runObjectContainers
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Get-WindowsUpdateStatus {
    <#
    .SYNOPSIS
        The Get-WindowsUpdateStatus function returns a "status" object (See outputs below) which summarizes the most important properties of a run by parsing the "run" object retrieve from the Get-WindowsUpdateRun function.
		
	.DESCRIPTION
		The Get-WindowsUpdateStatus function returns a "status" object (See outputs below) which summarizes the most important properties of a run by parsing the "run" object retrieve from the Get-WindowsUpdateRun function.
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER Id
        A variable used to group runs and query status information about them.
		
    .PARAMETER Version
        Currently not used. Could be used in the future to version the "run" objects if there are breaking changes to the formatting.
		
    .PARAMETER AsJob
        Runs the function as a job.
		
    .OUTPUTS
        Returns a "status" object containing:
        -------------------------------------------------------------------------------
        ComputerName : The computer name or IP address.
        Complete     : If the Install-WindowsUpdate function is complete or a terminating error occurred, this will be $true. Otherwise, it will be $false.
        Reboot       : If an update was installed on the current run that requires a reboot, this will be $true. Otherwise, it will be $false.
        Warning      : If a update failed to install on the current run, this will be $true. Otherwise, it will be $false.
        Error        : If a terminating error occurred that does not allow the Install-WindowsUpdate function to continue occurs, this will be $true. Otherwise, it will be $false.
        Run          : Each time the Install-WindowsUpdate function is run on a system, all matching Ids from previous runs are totaled to get the run count.
        Step         : An internal counter of current step within the script. This is mostly used for debug purposes. Look over the Install-WindowsUpdate function to see what i mean.
        Percent      : The percent complete on the current run. This is a simple calculation of current update / total updates * 100.
        Current      : The current update installing on the current run. For example, if there are 10 updates available and the it is on the second, it would be 2.
        Total        : The total updates available on the current run. For example, if there are 10 updates available, it would be 10.
        Installed    : The total number of updates installed across all runs.
        Message      : A status message about what the Install-WindowsUpdate function is currently doing. If an error occurs, it is displayed here as well.
        -------------------------------------------------------------------------------
		
	.EXAMPLE
		Get-WindowsUpdateStatus -ComputerName $computerName -Credential $credential -Id $id
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Version,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get required Get-WindowsUpdateRun function.
        $functionGetWindowsUpdateRun = Get-Item -Path ('function:\\Get-WindowsUpdateRun') -ErrorAction 'Stop'
        
        # Get status objects.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
            $Id
            $Version
            $functionGetWindowsUpdateRun
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            $Id = $args[5]
            $Version = $args[6]
            $functionGetWindowsUpdateRun = $args[7]

            # Import Get-WindowsUpdateRun function.
            $functionGetWindowsUpdateRunName = $functionGetWindowsUpdateRun.Name
            $functionGetWindowsUpdateRunScriptBlock = $functionGetWindowsUpdateRun.ScriptBlock
            $functionGetWindowsUpdateRunString = 'Function ' + $functionGetWindowsUpdateRunName + ' {' + $functionGetWindowsUpdateRunScriptBlock + '}'
            Invoke-Expression -Command $functionGetWindowsUpdateRunString

            # Get run object containers.
            $param = @{}
            if ($ComputerName) {
                $param.ComputerName = $ComputerName
                $param.Credential = $Credential
            }
            if ($Session) {
                $param.Session = $Session
            }
            if ($Id) {
                $param.Id = $Id
            }
            if ($Version) {
                $param.Version = $Version
            }
            $runObjectContainers = Get-WindowsUpdateRun @param
            
            # Get status objects.
            $statusObjects = if ($runObjectContainers) {

                # Get status objects.
                ForEach($runObjectContainer in $runObjectContainers) {

                    # Create status object.
                    $statusObject = New-Object -TypeName 'psobject'
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Complete' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Reboot' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Warning' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Error' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Run' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Step' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Percent' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Current' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Total' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Installed' -Value ''
                    $statusObject | Add-Member -MemberType 'NoteProperty' -Name 'Message' -Value ''

                    # Set number.
                    $statusObject.'#' = $runObjectContainer.'#'

                    # Set computer name.
                    $statusObject.ComputerName = $runObjectContainer.ComputerName

                    # Get status object values.
                    if ($runObjectContainer.Run) {

                        # Get run.
                        $run = $runObjectContainer.Run

                        # Get last run.
                        $runLast = $run | Select-Object -Last 1

                        # Get helper variables.
                        $runStatus = $runLast.Status
                        $runStatusLast = if ($runLast.Status) {
                            $runLast.Status | Select-Object -Last 1
                        }
                        $runStatusUpdate = $runLast.Status | Where-Object { $_.Update }
                        $runStatusUpdateLast = if ($runStatusUpdate) {
                            $runStatusUpdate | Select-Object -Last 1
                        }
                        $runStatusWarning = $runLast.Status | Where-Object { $_.Code -eq 2 }
                        $runStatusWarningLast = if ($runStatusWarning) {
                            $runStatusWarning | Select-Object -Last 1
                        }
                        $runStatusError = $runLast.Status | Where-Object { $_.Code -eq 3 }
                        $runStatusErrorLast = if ($runStatusError) {
                            $runStatusError | Select-Object -Last 1
                        }

                        # Set computer name.
                        # $statusObject.ComputerName = $runLast.ComputerName -as [String] # <- if enabled, IP address based 'ComputerName' will be replaced by actually computer name.

                        # Set complete.
                        $statusObject.Complete = if (($runLast.State -eq 'Complete' -or $runLast.Complete) `
                        -and ($runLast.Reboot -eq $false -or $runLast.Parameter.AutoRun -ne $true -or $runLast.Parameter.AutoReboot -ne $true -or $runLast.StopFile -eq $true)) {
                            $true
                        } else {
                            $false
                        }

                        # Set reboot.
                        $statusObject.Reboot = if ($runLast.Reboot) { $true } else { $false }

                        # Set warning
                        $statusObject.Warning = if ($runStatusWarning) { $true } else { $false }

                        # Set error
                        $statusObject.Error = if ($runStatusError) { $true } else { $false }

                        # Set run
                        $statusObject.Run = $runLast.Number

                        # Set step
                        $statusObject.Step = $runStatusLast.Step

                        # Set percent
                        $statusObject.Percent = if ($runStatusUpdateLast.Update) {
                            if ($runStatusUpdateLast.Update.Percent) {
                                [Math]::Round($runStatusUpdateLast.Update.Percent,0)
                            } else {
                                0
                            }
                        } elseif ($runStatusLast.Step -lt 7) { # Before downloading and installing updates.
                            0
                        } elseif ($runStatusLast.Step -eq 7) { # During downloading and installing updates.
                            0
                        } elseif ($runStatusLast.Step -gt 7) { # After downloading and installing updates.
                            100
                        } else {
                            'x' # Should not happen.
                        }

                        # Set current
                        $statusObject.Current = if ($runStatusUpdateLast.Update) {
                            if ($runStatusUpdateLast.Update.Number) {
                                $runStatusUpdateLast.Update.Number
                            } else {
                                0
                            }
                        } elseif ($runStatusLast.Step -gt 7 -and $runStatus.Step -notcontains 6) { # Checking for updates was skipped because a reboot was required.
                            '-'
                        } elseif ($runStatusLast.Step -lt 7) { # Before downloading and installing updates.
                            '-'
                        } elseif ($runStatusLast.Step -eq 7) { # During downloading and installing updates.
                            0
                        } elseif ($runStatusLast.Step -gt 7) { # After downloading and installing updates.
                            0
                        } else {
                            'x' # Should not happen.
                        }

                        # Set total
                        $statusObject.Total = if ($runLast.Update) {
                            if ([string]::IsNullOrEmpty($runLast.Update.Count)) {
                                1
                            } else {
                                $runLast.Update.Count
                            }
                        } elseif ($runStatusLast.Step -gt 7 -and $runStatus.Step -notcontains 6) { # Checking for updates was skipped because a reboot was required.
                            '-'
                        } elseif ($runStatusLast.Step -lt 7) { # Before downloading and installing updates.
                            '-'
                        } elseif ($runStatusLast.Step -eq 7) { # During downloading and installing updates.
                            0
                        } elseif ($runStatusLast.Step -gt 7) { # After downloading and installing updates.
                            0
                        } else {
                            'x' # Should not happen.
                        }

                        # Set installed
                        $statusObject.Installed = if ($run.Update) {
                            $runUpdateSucceeded = $run.Update | Where-Object { $_.Result -eq 'Succeeded' }
                            if ([string]::IsNullOrEmpty($runUpdateSucceeded.Count)) {
                                1
                            } else {
                                $runUpdateSucceeded.Count
                            }
                        } else {
                            0
                        }

                        # Set message
                        $statusObject.Message = if ($runStatusErrorLast) {
                            $runStatusErrorLast.Message
                        } elseif ($runStatusLast.Update.Title) {
                            $runStatusLast.Update.Title
                        } else {
                            $runStatusLast.Message
                        }
                    }

                    # Return status object.
                    $statusObject
                }
            }
        
            # Return status objects.
            if ($statusObjects) {
            
                # Sort status objects.
                $statusObjects = $statusObjects | Sort-Object -Property 'ComputerName'

                # Exclude pscomputername, psshowcomputername, and runspaceid.
                $statusObjects = $statusObjects | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                # Return status objects.
                $statusObjects
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Test-WindowsUpdateCompatible {
    <#
    .SYNOPSIS
        The Test-WindowsUpdateCompatible function tests if a computer is ready to use the Install-WindowsUpdate function and returns a "compatiblity" object (See outputs below).
	
	.DESCRIPTION
		The Test-WindowsUpdateCompatible function tests if a computer is ready to use the Install-WindowsUpdate function and returns a "compatiblity" object (See outputs below).
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER AsJob
		Runs the function as a job.
		
    .OUTPUTS
        Returns a "compatiblity" object containing:
        -------------------------------------------------------------------------------
        #               : Just a counter for convience.
        ComputerName    : The computer name or IP address.
        OSVersion       : The operating system version.
        PSVersion       : The PowerShell version.
        Compatible      : The overall compatibilty of the system. Contains $true if Ping, WinRM, OS, and PS are compatible. Contains $false if it isn't.
        PingCompatible  : Contains $true if the system is pingable. Contains $false if it isn't.
        WinRMCompatible : Contains $true if the system is connectable through WinRM. Contains $false if it isn't.
        OSCompatible    : Contains $true if the system is running a compatible OS. Contains $false if it isn't.
        PSCompatible    : Contains $true if the system is running a compatible PowerShell version. Contains $false if it isn't.
        -------------------------------------------------------------------------------
		
	.EXAMPLE
		Test-WindowsUpdateCompatible -ComputerName $computerName -Credential $credential
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get run object containers online.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
        )
        $param.ScriptBlock = {
			
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            
            try {

                # Get computer names online.
                $computerNameOnline = @(
                    if ($ComputerName) {
                        ForEach ($computer in $ComputerName) {
                            if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
                                $computer
                            } else {
                                #Write-Warning "${command}: $computer is offline."
                            }
                        }
                    }
                )

                # Get computer names offline.
                $ComputerNameOffline = @(
                    if ($ComputerName) {
                        $ComputerName | Where-Object { $computerNameOnline -notcontains $_ }
                    }
                )
        
                # Get sessions online.
                $sessionOnline = @(
                    if ($Session) {
                        ForEach ($sess in $Session) {
                            if ($sess.State -eq 'Opened' -and $sess.Availability -eq 'Available' -and (Test-Connection -ComputerName $sess.ComputerName -Count 1 -Quiet)) {
                                $sess
                            } else {
                                #Write-Warning "${command}: $($sess.ComputerName) is offline."
                            }
                        }
                    }
                )

                # Get sessions offline.
                $sessionOffline = @(
                    if ($Session) {
                        $Session | Where-Object { $sessionOnline.ComputerName -notcontains $_.ComputerName }
                    }
                )

                # Get compatibility objects.
                $compatiblityObjects = @(
            
                    # Test online computers and sessions.
                    if ($computerNameOnline -or $sessionOnline) {
            
                        # Get compatibility objects.
                        if ($Credential -or $Session) {

                            # Get compatibility objects.
                            try {

                                $param = @{}
                                if ($computerNameOnline) {
                                    $param.ComputerName = $computerNameOnline
                                    $param.Credential = $Credential
                                    $param.SessionOption = New-PSSessionOption -NoMachineProfile
                                }
                                if ($sessionOnline) {
                                    $param.Session = $sessionOnline
                                }
                                $param.ThrottleLimit = 200
                                $param.ErrorAction = 'Stop'
                                $param.ArgumentList = @(
                                    $VerbosePreference
                                    $command
                                )
                                $param.ScriptBlock = {

                                    # Set variables
                                    $VerbosePreference = $args[0]
                                    $command = $args[1]

                                    try {

                                        # Set environment variables.
                                        $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                                        # Write verbose.
                                        Write-Verbose -Message "${command}: $envComputerName."

                                        # Create compatibility object.
                                        $compatiblityObject = New-Object -TypeName 'psobject'
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSVersion' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'Compatible' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PingCompatible' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'WinRMCompatible' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSCompatible' -Value ''
                                        $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSCompatible' -Value ''

                                        # Set ping compatible.
                                        $compatiblityObject.PingCompatible = $true

                                        # Set wsman compatible.
                                        $compatiblityObject.WinRMCompatible = $true

                                        # Set os version.
                                        $compatiblityObject.OSVersion = [environment]::OSVersion.Version

                                        # Set os compatible.
                                        $compatiblityObject.OSCompatible = ([environment]::OSVersion.Version.Major -gt 6 -or ([environment]::OSVersion.Version.Major -eq 6 -and [environment]::OSVersion.Version.Minor -gt 0))

                                        # Set ps version.
                                        $compatiblityObject.PSVersion = $PSVersionTable.PSVersion

                                        # Set ps compatible.
                                        $compatiblityObject.PSCompatible = $PSVersionTable.PSVersion -ge '2.0'

                                        # Set compatible
                                        $compatiblityObject.Compatible = $compatiblityObject.OSCompatible -and $compatiblityObject.PSVersion -and $compatiblityObject.PSCompatible

                                        # Return compatibility object.
                                        $compatiblityObject

                                    } catch {
                            
                                        # Write error.
                                        Write-Error -ErrorRecord $_

                                    }
                                }
                                Invoke-Command @param

                            } catch {

                                # Set environment variables.
                                $envComputerName = $_.TargetObject

                                # Write verbose.
                                Write-Warning "${command}: $($_.TargetObject) session failed."

                                # Create compatibility object.
                                $compatiblityObject = New-Object -TypeName 'psobject'
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'Compatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PingCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'WinRMCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSCompatible' -Value ''

                                # Set computer name.
                                $compatiblityObject.ComputerName = $envComputerName

                                # Set ping compatible.
                                $compatiblityObject.PingCompatible = $true

                                # Set wsman compatible.
                                $compatiblityObject.WinRMCompatible = $false

                                # Set compatible.
                                $compatiblityObject.Compatible = $false

                                # Return compatibility object.
                                $compatiblityObject

                            }
            
                        } else {
                
                            # Get compatibility objects.
                            $job = ForEach($computer in $computerNameOnline) {
                                $param = @{
                                    ArgumentList = @(
                                        $VerbosePreference
                                        $command
                                        $computer
                                    )
                                    ScriptBlock = {

                                        # Set variables
                                        $VerbosePreference = $args[0]
                                        $command = $args[1]
                                        $computer = $args[2]

                                        try {

                                            # Set environment variables.
                                            $envComputerName = $computer

                                            # Write verbose.
                                            Write-Verbose -Message "${command}: $envComputerName."

                                            # Create compatibility object.
                                            $compatiblityObject = New-Object -TypeName 'psobject'
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSVersion' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'Compatible' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PingCompatible' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'WinRMCompatible' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSCompatible' -Value ''
                                            $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSCompatible' -Value ''

                                            # Set computer name.
                                            $compatiblityObject.ComputerName = $envComputerName

                                            # Set ping compatible.
                                            $compatiblityObject.PingCompatible = $true

                                            # Set wsman compatible.
                                            $compatiblityObject.WinRMCompatible = $false

                                            # Set wsman compatible.
                                            $compatiblityObject.WinRMCompatible = try {
                                                $param = @{
                                                    ComputerName = $envComputerName
                                                    ErrorAction = 'Stop'
                                                }
                                                Test-WSMan @param | Out-Null
                                                $true
                                            } catch {
                                                $false
                                            }

                                            # Set compatible.
                                            $compatiblityObject.Compatible = $compatiblityObject.WinRMCompatible

                                            # Return compatibility object.
                                            $compatiblityObject

                                        } catch {
                            
                                            # Write error.
                                            Write-Error -ErrorRecord $_

                                        }
                                    }
                                }
                                Start-Job @param
                            }
            
                            # Wait job.
                            Wait-Job -Job $job | Out-Null

                            # Receive compatiblity objects.  
                            Receive-Job -Job $job
                        }
                    }
            
                    # Test offline computers and sessions.
                    if ($ComputerNameOffline -or $sessionOffline) {
                
                        if ($ComputerNameOffline) {
                            ForEach ($computer in $ComputerNameOffline) {
                
                                # Set environment variables.
                                $envComputerName = $computer

                                # Write verbose.
                                Write-Verbose -Message "${command}: $envComputerName."

                                # Create compatibility object.
                                $compatiblityObject = New-Object -TypeName 'psobject'
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'Compatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PingCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'WinRMCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSCompatible' -Value ''

                                # Set computer name.
                                $compatiblityObject.ComputerName = $envComputerName

                                # Set ping compatible.
                                $compatiblityObject.PingCompatible = $false

                                # Set compatible
                                $compatiblityObject.Compatible = $false

                                # Return compatibility object.
                                $compatiblityObject
                            }
                        }

                        if ($sessionOffline) {
                            ForEach ($computer in $sessionOffline.ComputerName) {
                
                                # Set environment variables.
                                $envComputerName = $computer

                                # Write verbose.
                                Write-Verbose -Message "${command}: $envComputerName."

                                # Create compatibility object.
                                $compatiblityObject = New-Object -TypeName 'psobject'
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSVersion' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'Compatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PingCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'WinRMCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'OSCompatible' -Value ''
                                $compatiblityObject | Add-Member -MemberType 'NoteProperty' -Name 'PSCompatible' -Value ''

                                # Set computer name.
                                $compatiblityObject.ComputerName = $envComputerName

                                # Set ping compatible.
                                $compatiblityObject.PingCompatible = $false

                                # Set compatible
                                $compatiblityObject.Compatible = $false

                                # Return compatibility object.
                                $compatiblityObject
                            }
                        }
                    }
                )

                # Return compatibility objects.
                if ($compatiblityObjects) {

                    # Add ComputerName to compatibility objects.
                    if ($Credential -or $Session) {
                        $count = 0
                        ForEach($compatiblityObject in $compatiblityObjects) {
                            if (!$compatiblityObject.ComputerName) {
                                $compatiblityObject.ComputerName = $compatiblityObjects[$count].PSComputerName
                            }
                            $count += 1
                        }
                    }

                    # Sort container objects.
                    $compatiblityObjects = $compatiblityObjects | Sort-Object -Property 'ComputerName'
            
                    # Add # to compatibility objects.
                    $count = 1
                    ForEach($compatiblityObject in $compatiblityObjects) {
                        $compatiblityObject.'#' = $count
                        $count += 1
                    }

                    # Exclude pscomputername, psshowcomputername, and runspaceid.
                    $compatiblityObjects = $compatiblityObjects | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                    # Return container objects.
                    $compatiblityObjects
                }

            } catch {

                # Write error.
                Write-Error -ErrorRecord $_

            } finally {
                   
                # Remove job.
                if ($job) {
                    Remove-Job -Job $job -Force -ErrorAction 'SilentlyContinue'
                }
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Disable-WindowsUpdate {
    <#
    .SYNOPSIS
        The Disable-WindowsUpdate function disables the Install-WindowsUpdates function from running on a system. If the Install-WindowsUpdates function is currently running, it is stopped after the current update is completed.
		
	.DESCRIPTION
		The Disable-WindowsUpdate function disables the Install-WindowsUpdates function from running on a system. If the Install-WindowsUpdates function is currently running, it is stopped after the current update is completed.
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER AsJob
		Runs the function as a job.
		
	.OUTPUTS
		None.
		
	.EXAMPLE
		Disable-WindowsUpdate -ComputerName $computerName -Credential $credential
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Add stop file.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]

            # Add stop file.
            $param = @{}
            if ($ComputerName) {
                $param.ComputerName = $ComputerName
                $param.Credential = $Credential
                $param.SessionOption = New-PSSessionOption -NoMachineProfile
            }
            if ($Session) {
                $param.Session = $Session
            }
            $param.ThrottleLimit = 200
            $param.ArgumentList = @(
                $VerbosePreference
                $command
            )
            $param.ScriptBlock = {
                
                # Set variables.
                $VerbosePreference = $args[0]
                $command = $args[1]

                # Set environment variables.
                $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                # Write verbose.
                Write-Verbose -Message "${command}: $envComputerName."

                # Add stop file.
                $stopFilePath = $env:ProgramData + '\Stop-WindowsUpdate.txt'
                if (!(Test-Path -Path $stopFilePath)) {
                    Out-File -FilePath $stopFilePath -Force
                }
            }
            Invoke-Command @param
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Enable-WindowsUpdate {
    <#
    .SYNOPSIS
        The Enable-WindowsUpdate function enables the Install-WindowsUpdates function if it was previously disabled on a system.
		
	.DESCRIPTION
		The Enable-WindowsUpdate function enables the Install-WindowsUpdates function if it was previously disabled on a system.
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER AsJob
		Runs the function as a job.
		
	.OUTPUTS
		None.
		
	.EXAMPLE
		Enable-WindowsUpdate -ComputerName $computerName -Credential $credential
    #> 
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Remove stop file.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]

            $param = @{}
            if ($ComputerName) {
                $param.ComputerName = $ComputerName
                $param.Credential = $Credential
                $param.SessionOption = New-PSSessionOption -NoMachineProfile
            }
            if ($Session) {
                $param.Session = $Session
            }
            $param.ThrottleLimit = 200
            $param.ArgumentList = @(
                $VerbosePreference
                $command
            )
            $param.ScriptBlock = {
                
                # Set variables.
                $VerbosePreference = $args[0]
                $command = $args[1]

                # Set environment variables.
                $envComputerName = ([System.Net.Dns]::GetHostByName($Env:ComputerName)).HostName.ToLower()

                # Write verbose.
                Write-Verbose -Message "${command}: $envComputerName."

                # Remove stop file.
                $stopFilePath = $env:ProgramData + '\Stop-WindowsUpdate.txt'
                if (Test-Path -Path $stopFilePath) {
                    Remove-Item -Path $stopFilePath -Force
                }
            }
            Invoke-Command @param
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}

Function Wait-WindowsUpdate {
    <#
    .SYNOPSIS
        The Wait-WindowsUpdate function waits for the Install-WindowsUpdates function to complete then returns a "wait" object (See outputs below).
		
	.DESCRIPTION
		The Wait-WindowsUpdate function waits for the Install-WindowsUpdates function to complete then returns a "wait" object (See outputs below).
		
    .PARAMETER ComputerName
        The computer(s) to execute the function on.
		
    .PARAMETER Credential
        The credentials to use to connect to the computer(s).
		
    .PARAMETER Session
        The session(s) to execute the function on.
		
    .PARAMETER Id
        A variable used to group runs and query status information about them.
		
    .PARAMETER Version
        Currently not used. Could be used in the future to version the "run" objects if there are breaking changes to the formatting.
		
    .PARAMETER AsJob
        Runs the function as a job.
		
    .OUTPUTS
        Returns a "wait" object containing:
        -------------------------------------------------------------------------------
        #            : Just a counter for convience.
        ComputerName : The computer name or IP address.
        Result       : Contains "Succeeded" if the Wait-WindowsUpdate function successfully waited for all updates to complete. Contains "Failed" if there was an error or the wait timed out.
        -------------------------------------------------------------------------------
		
	.EXAMPLE
		Wait-WindowsUpdate -ComputerName $computerName -Credential $credential -Id $id
    #>
    [CmdletBinding(DefaultParameterSetName='Computer')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [String[]]
        $ComputerName,

        [Parameter(Mandatory = $true, ParameterSetName='Computer')]
        [System.Management.Automation.PSCredential]
        $Credential,

        [Parameter(Mandatory = $true, ParameterSetName='Session')]
        [System.Management.Automation.Runspaces.PSSession[]]
        $Session,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [String]
        $Id,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Int]
        $Version,

        [Parameter()]
        [Int]
        $Timeout = 86400, # 24 hours.

        [Parameter()]
        [Switch]
        $AsJob
    )
    
    try {

        # Set command name.
        $command = $MyInvocation.MyCommand.Name

        # Get required Get-WindowsUpdateRun function.
        $functionGetWindowsUpdateRun = Get-Item -Path ('function:\\Get-WindowsUpdateRun') -ErrorAction 'Stop'

        # Get required Get-WindowsUpdateStatus function.
        $functionGetWindowsUpdateStatus = Get-Item -Path ('function:\\Get-WindowsUpdateStatus') -ErrorAction 'Stop'

        # Get wait objects.
        $param = @{}
        $param.ArgumentList = @(
            $VerbosePreference
            $command
            ,$ComputerName
            $Credential
            ,$Session
            $Id
            $Version
            $Timeout
            $functionGetWindowsUpdateRun
            $functionGetWindowsUpdateStatus
        )
        $param.ScriptBlock = {
            
            # Set variables.
            $VerbosePreference = $args[0]
            $command = $args[1]
            $ComputerName = $args[2]
            $Credential = $args[3]
            $Session = $args[4]
            $Id = $args[5]
            $Version = $args[6]
            $Timeout = $args[7]
            $functionGetWindowsUpdateRun = $args[8]
            $functionGetWindowsUpdateStatus = $args[9]

            # Create format time span funtion.
            function Format-TimeSpanString {
                [CmdletBinding()]
                param(
                    [TimeSpan]$TimeSpan
                )
    
                $string = ''
                if ($TimeSpan.Days) { $string += "$($TimeSpan.Days) Day" ; if ($TimeSpan.Days -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
                if ($TimeSpan.Hours) { $string += "$($TimeSpan.Hours) Hour" ; if ($TimeSpan.Hours -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
                if ($TimeSpan.Minutes) { $string += "$($TimeSpan.Minutes) Minute" ; if ($TimeSpan.Minutes -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
                if ($TimeSpan.Seconds) { $string += "$($TimeSpan.Seconds) Second" ; if ($TimeSpan.Seconds -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
                #if ($TimeSpan.Milliseconds) { $string += "$($TimeSpan.Milliseconds) Millisecond" ; if ($TimeSpan.Days -eq 1 ) { $string += ', ' } else { $string += 's, ' } }
                if (!$TimeSpan.Days -and !$TimeSpan.Hours -and !$TimeSpan.Minutes -and !$TimeSpan.Seconds) { $string = '1 Second' }
                $string -replace ', $'
            }

            # Import Get-WindowsUpdateRun function.
            $functionGetWindowsUpdateRunName = $functionGetWindowsUpdateRun.Name
            $functionGetWindowsUpdateRunScriptBlock = $functionGetWindowsUpdateRun.ScriptBlock
            $functionGetWindowsUpdateRunString = 'Function ' + $functionGetWindowsUpdateRunName + ' {' + $functionGetWindowsUpdateRunScriptBlock + '}'
            Invoke-Expression -Command $functionGetWindowsUpdateRunString

            # Import Get-WindowsUpdateStatus function.
            $functionGetWindowsUpdateStatusName = $functionGetWindowsUpdateStatus.Name
            $functionGetWindowsUpdateStatusScriptBlock = $functionGetWindowsUpdateStatus.ScriptBlock
            $functionGetWindowsUpdateStatusString = 'Function ' + $functionGetWindowsUpdateStatusName + ' {' + $functionGetWindowsUpdateStatusScriptBlock + '}'
            Invoke-Expression -Command $functionGetWindowsUpdateStatusString

            # Get complete count.
            $completeCount = 0
            $completeCountTotal = if ($ComputerName) {
                if ([string]::IsNullOrEmpty($ComputerName.Count)) { 1 } else { $ComputerName.Count }
            } elseif ($Session) {
                if ([string]::IsNullOrEmpty($Session.Count)) { 1 } else { $Session.Count }
            }

            # Get running list.
            $runningList = if ($ComputerName) {
                $ComputerName
            } elseif ($Session) {
                $Session
            }
            $runningListComputers = if ($ComputerName) {
                $ComputerName
            } elseif ($Session) {
                $Session.ComputerName
            }

            # Get complete list.
            $completeList = @()
            $completeListComputers = @()

            # Create wait objects.
            $waitObjects = ForEach($runningListComputer in $runningListComputers) {
                $waitObject = New-Object -TypeName 'psobject'
                $waitObject | Add-Member -MemberType 'NoteProperty' -Name '#' -Value ''
                $waitObject | Add-Member -MemberType 'NoteProperty' -Name 'ComputerName' -Value $runningListComputer
                $waitObject | Add-Member -MemberType 'NoteProperty' -Name 'Result' -Value 'Failed'
                $waitObject
            }

            # Get status objects parameters.
            $param = @{}
            if ($ComputerName) {
                $param.ComputerName = $ComputerName
                $param.Credential = $Credential
            }
            if ($Session) {
                $param.Session = $Session
            }
            if ($Id) {
                $param.Id = $Id
            }
            if ($Version) {
                $param.Version = $Version
            }

            # Set script start.
            $scriptStart = Get-Date

            # Wait for Install-WindowsUpdate to complete.
            While($true) {

                # Get status objects.
                $statusObjects = Get-WindowsUpdateStatus @param

                # Get complete status objects.
                $statusObjectsComplete = $statusObjects | Where-Object { $_.Complete -eq $true } 

                # Get the ongoing running and complete list.
                if ($statusObjectsComplete) {

                    if ($ComputerName) {
                        ForEach ($statusObjectComplete in $statusObjectsComplete) {
                            $completeList += $runningList | Where-Object { $_ -eq $statusObjectComplete.ComputerName }
                            $completeListComputers = $completeList
                            $runningList = $runningList | Where-Object { $_ -ne $statusObjectComplete.ComputerName }
                            $runningListComputers = $runningList
                            $waitObject = $waitObjects | Where-Object { $_.ComputerName -eq $statusObjectComplete.ComputerName }
                            $waitObject.Result = 'Succeeded'
                        }
                        $param.ComputerName = $runningList
                    }
                    if ($Session) {
                        ForEach ($statusObjectComplete in $statusObjectsComplete) {
                            $completeList += $runningList | Where-Object { $_.ComputerName -eq $statusObjectComplete.ComputerName }
                            $completeListComputers = $completeList.ComputerName
                            $runningList = $runningList | Where-Object { $_.ComputerName -ne $statusObjectComplete.ComputerName }
                            $runningListComputers = $runningList.ComputerName
                            $waitObject = $waitObjects | Where-Object { $_.ComputerName -eq $statusObjectComplete.ComputerName }
                            $waitObject.Result = 'Succeeded'
                        }
                        $param.Session = $runningList
                    }

                    $completeCount = if ($completeList) {
                        if ([string]::IsNullOrEmpty($completeList.Count)) { 1 } else { $completeList.Count }
                    } else {
                        0
                    }
                    $runningCount = if ($runningList) {
                        if ([string]::IsNullOrEmpty($runningList.Count)) { 1 } else { $runningList.Count }
                    } else {
                        0
                    }
                }

                # Write verbose.
                $scriptDuration = (Get-Date) - $scriptStart
                $scriptDurationString = Format-TimeSpanString -TimeSpan $scriptDuration
                Write-Verbose -Message "${command}: $completeCount of $completeCountTotal computers complete after waiting $scriptDurationString."

                # Check if status objects match the expected count.
                if ($completeCount -eq $completeCountTotal) {
                    break
                } elseif ($scriptDuration.TotalSeconds -gt $Timeout) {
                    $runningCount = if ($runningList) {
                        if ([string]::IsNullOrEmpty($runningList.Count)) { 1 } else { $runningList.Count }
                    } else {
                        0
                    }
                    Write-Warning -Message "${command}: $runningCount computers timed out."
                    ForEach ($runningListComputer in $runningListComputers) {
                        Write-Warning -Message "${command}: Timed out waiting for $runningListComputer to complete."
                    }
                    break
                } else {
                    Start-Sleep -Seconds 60
                }
            }

            # Return wait objects.
            if ($waitObjects) {

                # Sort wait objects.
                $waitObjects = $waitObjects | Sort-Object -Property 'ComputerName'
            
                # Add # to wait objects.
                $count = 1
                ForEach($waitObject in $waitObjects) {
                    $waitObject.'#' = $count
                    $count += 1
                }

                # Exclude pscomputername, psshowcomputername, and runspaceid.
                $waitObjects = $waitObjects | Select-Object -Property * -ExcludeProperty 'PSComputerName','PSShowComputerName','RunspaceID'

                # Return wait objects.
                $waitObjects
            }
        }
        if ($AsJob) {
            Start-Job @param
        } else {
            Invoke-Command @param
        }

    } catch {

        # Write error.
        Write-Error -ErrorRecord $_

    }
}
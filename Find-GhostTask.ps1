 function Find-GhostTask {
    param (
        [switch]$defaultSDDL,
        [switch]$detail
    )

    # Define the base path for the registry key
    $basePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"

    # Define the path for the 'Tasks' subkey
    $tasksBasePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

    # Define the ACL strings to look for
    $aclStringToFind = "O:BAG:SYD:(A;OICIID;CCSWRPSDRC;;;BA)(A;OICIID;KA;;;SY)"
    $additionalAclStringToFind = "O:BAG:SYD:AI(A;OICIID;CCSWRPSDRC;;;BA)(A;OICIID;KA;;;SY)"
    $thirdAclStringToFind = "O:SYG:SYD:P(A;OICI;KA;;;SY)(A;OICI;CCSWRPSDRC;;;BA)"

    # Array to store the IDs
    $idValuesArray = @()

    # Counter for iterations
    $iterationCount = 0

    $Path = $basePath
    # Get all subkeys under the current path
    $subkeys = Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue

    foreach ($key in $subkeys) {
        # Skip if the current item is not a Registry Key
        if ($key -isnot [Microsoft.Win32.RegistryKey]) { continue }

        $sdExists = $false
        $aclMatch = $false
        $hashMatch = $false
        $indexMatch = $false
        $actionFlag = $false
        $noIndex = $false
        $idValue = $null
        $indexData = $null

        try {
            # Attempt to retrieve the 'Actions' REG_BINARY value under the "Tasks" subkey with the corresponding ID
            $idValue = Get-ItemProperty -Path $key.PSPath -Name "Id" -ErrorAction SilentlyContinue
            if ($idValue."Id") {
                $actionsPath = "$tasksBasePath\$($idValue.Id)"
                $actionsValue = Get-ItemProperty -Path $actionsPath -Name "Actions" -ErrorAction SilentlyContinue
                if ($actionsValue."Actions") {
                    $actionFlag = $true
                }
            }
        } catch {
            Write-Error "An error occurred while checking for Actions with ID value: $_"
        }

        $indexValue = Get-ItemProperty -Path $key.PSPath -Name "Index" -ErrorAction SilentlyContinue

        # Check if the 'Index' property exists and is not null
        if ($null -ne $indexValue.'Index') {
            $noIndex = $false
            # Store the index data for output
            $indexData = $indexValue.'Index'
            if ($indexData -eq 0) {
                $indexMatch = $true
            }
        } else {
            if ($actionFlag) {
                $noIndex = $true
            }
        }

        # Attempt to retrieve the 'SD' REG_BINARY value for the key
        $sdValue = Get-ItemProperty -Path $key.PSPath -Name "SD" -ErrorAction SilentlyContinue
        if ($sdValue."SD") {
            $sdExists = $true

            $binaryData = $sdValue."SD"
            $hasher = [System.Security.Cryptography.SHA256]::Create()
            $hashBytes = $hasher.ComputeHash($binaryData)
            $hasher.Dispose()
            $hashString = [BitConverter]::ToString($hashBytes) -replace '-'
            
            # Compare the hash against the specified value
            $targetHash = "6A45225721B4FC90950C526F55C561CB02CE6F9896F57191BD6FD71EFE3ECB4C"
            if ($hashString -eq $targetHash) {
                $hashMatch = $true
            }
        }

        # Attempt to retrieve the ACL for the key
        $acl = Get-Acl -Path $key.PSPath -ErrorAction SilentlyContinue
        if ($acl) {
            # Convert the ACL to a string for pattern matching
            $aclString = $acl.Sddl
            # Check if the specific ACL pattern exists
            if ($aclString -like "*$aclStringToFind*" -or $aclString -like "*$additionalAclStringToFind*") {
                $aclMatch = $true
            }
            # Check for the third ACL pattern if the -defaultSDDL flag is specified
            if ($defaultSDDL -and $aclString -like "*$thirdAclStringToFind*") {
                $aclMatch = $true
            }
        }

        # If no 'SD' value exists or a matching ACL, hash, or index is found, and the action flag is true
        if (-not $sdExists -or $noIndex -or $aclMatch -or $hashMatch -or $indexMatch -and $actionFlag) {
            # Increase the iteration count
            $iterationCount++

            # Display a separator line from the second iteration onwards
            if ($iterationCount -gt 1) {
                Write-Host ""
                Write-Host "=======================" -ForegroundColor White
                Write-Host ""
            }

            try {
                $idValue = Get-ItemProperty -Path $key.PSPath -Name "Id" -ErrorAction SilentlyContinue
                if ($idValue."Id") {
                    
                    if ($noIndex -and $actionFlag) {
                        Write-Host "!!! " -NoNewline -ForegroundColor Magenta
                        Write-Host "No index value exists for $($key.Name): " -ForegroundColor Red -NoNewline
                        Write-Host $idValue."Id" -ForegroundColor Magenta 
                    }

                    if (-not $sdExists) {
                        Write-Host "!!! " -NoNewline -ForegroundColor Magenta
                        Write-Host "No SD value exists for $($key.Name): " -ForegroundColor Red -NoNewline
                        Write-Host $idValue."Id" -ForegroundColor Magenta
                    
                    } else {
                        if ($hashMatch) {
                            Write-Host "!!! " -NoNewline -ForegroundColor Magenta
                            Write-Host "Matching SD signature found for $($key.Name): " -ForegroundColor Red -NoNewline
                            Write-Host $idValue."Id" -ForegroundColor Magenta
                        }
                    }

                    if ($aclMatch) {
                        Write-Host "!!! " -NoNewline -ForegroundColor Magenta
                        Write-Host "Matching ACL found for $($key.Name): " -ForegroundColor Red -NoNewline
                        Write-Host $idValue."Id" -ForegroundColor Magenta
                    }
                    if($detail) { $acl | Format-List | Out-String | Write-Host }

                    #Write-Host "Id value for $($key.Name): $($idValue.Id)"
                    $idValuesArray += $idValue."Id"

                    # Now check for the "Actions" REG_BINARY value under the "Tasks" subkey with the corresponding ID
                    $actionsPath = "$tasksBasePath\$($idValue.Id)"
                    $actionsValue = Get-ItemProperty -Path $actionsPath -Name "Actions" -ErrorAction SilentlyContinue
                    $descValue = Get-ItemProperty -Path $actionsPath -Name "Description" -ErrorAction SilentlyContinue
                    $authorValue = Get-ItemProperty -Path $actionsPath -Name "Author" -ErrorAction SilentlyContinue

                    if ($indexMatch -and $actionFlag) {
                        Write-Host "!!! " -NoNewline -ForegroundColor Magenta
                        Write-Host "Hidden index value ($indexData) found for $($key.Name): " -ForegroundColor Red -NoNewline
                        Write-Host $idValue."Id" -ForegroundColor Magenta
                    }
                                        
                    if ($authorValue) {
                        Write-Host "Author: " -ForegroundColor Red -NoNewline
                        Write-Host $authorValue."Author" -ForegroundColor DarkRed
                    }
                    if ($descValue) {
                        Write-Host "Description: " -ForegroundColor Red -NoNewline
                        Write-Host $descValue."Description" -ForegroundColor DarkRed
                    }

                    if ($actionFlag) {
                        if($detail) { Write-Host "Actions REG_BINARY value found for Id $($idValue.Id)" }
                        # Convert and output the "Actions" REG_BINARY value in hex format
                        $binaryData = $actionsValue."Actions"
                        $hexOutput = $binaryData | Format-Hex | Out-String
                        if($detail) { Write-Host $hexOutput }
                        # Attempt to decode the binary data to UTF-16LE string and remove null characters
                        $decodedString = [System.Text.Encoding]::Unicode.GetString($binaryData).Replace("`0", "")
                        # Replace "Author晦" if found in the decoded string
                        $decodedString = $decodedString.Replace("Author晦", "")
                        Write-Host "Decoded 'Actions' value: " -ForegroundColor Red -NoNewline
                        Write-Host "$decodedString" -ForegroundColor Magenta
                        
                        # Use a case-insensitive regex match to find "powershell" and "-enc"
                        if ($decodedString -match 'powershell.*?-enc.*?\s+"([A-Za-z0-9+/=]+)"') {
                            # Extract the base64 string between the quotes after "-enc"
                            $base64String = $matches[1]
                            Write-Host "*** " -ForegroundColor DarkRed -NoNewline
                            # Decode the base64 string
                            try {
                                $bytes = [Convert]::FromBase64String($base64String)
                                $decodedCommand = [System.Text.Encoding]::Unicode.GetString($bytes)
                                Write-Host "Decoded PowerShell Command: " -NoNewline
                                Write-Host "$decodedCommand" -ForegroundColor Yellow
                            } catch {
                                Write-Error "Failed to decode base64 string: $_"
                            }
                        }
                    }
                }
            }
            catch {
                Write-Error "An error occurred while processing $($key.Name): $_"
            }
        }
    }

    if ($idValuesArray.Count -gt 0) {
        Write-Host ""
        Write-Host "=======================" -ForegroundColor White
        Write-Host ""
        Write-Host "Total ghost tasks found: $($idValuesArray.Count)" -ForegroundColor Red
        Write-Host "List of Ids:" -ForegroundColor Red
        $idValuesArray | ForEach-Object { Write-Host $_ -ForegroundColor Magenta}
    } else {
        Write-Host "No ghost tasks found." -ForegroundColor Green
    }

}
Find-GhostTask 

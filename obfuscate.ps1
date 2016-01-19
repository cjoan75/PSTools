<#
    A comment block that will remain after obfuscate.ps1 runs
    to allow for inline help, copyright notices, and any other introductory
    text desired.
    
    Ref: http://desktoplibrary.livelink-experts.com/obfuscate-powershell
#>

param(
  [parameter(Mandatory=$false)]
  [string]$param1
)

# this function will keep name
function donothing($local:arg1, $local:arg2) { return $null } 

# this function will lose the name to "GATEVILLAGE<guid>"
function dosomething($local:arg1, $local:arg2) {
    $local:mess =  'dosomething, like arg1= "' + $local:arg1 + '" arg2= "' + $local:arg2 + '"'
    return $local:mess
}

<#
   A comment block that will not get removed
#>

# followed by a comment that will get removed

$local:thisvar = 'variable, called thisvar, will get renamed' # and this comment will get removed as well

# and this one
$local:thatvar = 'variable, called thatvar, will not get renamed because it is part of notouch'

$script:name = "Desktop Library"
$script:firstarg = $local:thisvar     # set the first argment to thisvar 
$script:secondarg = $local:thatvar    # set the second argument to thatvar

if ($script:name -eq "Desktop Library") {
    if ((donothing $firstarg $secondarg) -eq $null) { dosomething $firstarg $secondarg }
}

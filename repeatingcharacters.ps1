function get-duplicatechar {
 [CmdletBinding()]
  param (
     [string]$teststring
   )
   $DupeArray = ($teststring.ToCharArray() | Group | Select Count, Name | Where -Property Count -ne 1)
if($teststring.ToCharArray() | Group | Select Count, Name | Where -Property Count -ne 1)
{
$DupeArray[0] | Select Name
}
else
{
"All Unique"
}}
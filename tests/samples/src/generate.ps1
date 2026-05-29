$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$root='C:\ait'; $dl="$root\dl"; $ver="$root\versions"; $src="$root\src"; $gen="$root\gen"
New-Item -ItemType Directory -Force -Path $dl,$ver,$gen | Out-Null
$base='https://www.autoitscript.com/autoit3/files/archive/autoit/'
$versions = '3.1.0','3.1.1','3.2.0.1','3.2.2.0','3.2.4.9','3.2.6.0','3.2.8.1','3.3.8.1','3.3.10.2','3.3.12.0','3.3.14.0','3.3.14.5','3.3.16.1','3.3.18.0'

function Run($exe,$argList){
  $p=Start-Process -FilePath $exe -ArgumentList $argList -PassThru -NoNewWindow
  if(-not $p.WaitForExit(90000)){ try{$p.Kill()}catch{}; return 'TIMEOUT' }
  return $p.ExitCode
}

Set-Location $src
foreach($v in $versions){
  try {
    $f="autoit-v$v.zip"; $out="$dl\$f"
    if(-not(Test-Path $out)){ Invoke-WebRequest -UseBasicParsing -Uri ($base+$f) -OutFile $out -TimeoutSec 180 }
    $d="$ver\$v"; if(-not(Test-Path "$d\.done")){ if(Test-Path $d){Remove-Item -Recurse -Force $d}; Expand-Archive -Path $out -DestinationPath $d -Force; New-Item -ItemType File -Force "$d\.done" | Out-Null }
    # locate compilers
    $all = Get-ChildItem -Recurse $d -Filter '*.exe' | Where-Object { $_.Name -match '^Aut2[Ee]xe' }
    $def = $all | Where-Object { $_.Name -match '^Aut2[Ee]xe\.exe$' } | Select-Object -First 1
    $ansi= $all | Where-Object { $_.Name -match '^Aut2exeA\.exe$' }     | Select-Object -First 1
    $x64 = $all | Where-Object { $_.Name -match '^Aut2exe_x64\.exe$' }  | Select-Object -First 1
    $tag = $v -replace '\.',''
    $results=@()
    if($def){
      $o="$gen\v${tag}_def.exe"; $rc=Run $def.FullName @('/in',"$src\fixture.au3",'/out',$o); $results+="def=$rc/$([bool](Test-Path $o))"
      $a="$gen\v${tag}.a3x";     $rc=Run $def.FullName @('/in',"$src\fixture.au3",'/out',$a); $results+="a3x=$rc/$([bool](Test-Path $a))"
    }
    if($ansi){ $o="$gen\v${tag}_ansi.exe"; $rc=Run $ansi.FullName @('/in',"$src\fixture.au3",'/out',$o); $results+="ansi=$rc/$([bool](Test-Path $o))" }
    if($x64){ $o="$gen\v${tag}_x64.exe"; $rc=Run $x64.FullName @('/in',"$src\fixture.au3",'/out',$o); $results+="x64=$rc/$([bool](Test-Path $o))" }
    "[$v] def=$([bool]$def) ansi=$([bool]$ansi) x64=$([bool]$x64) :: $($results -join '  ')"
  } catch { "[$v] ERR: $($_.Exception.Message)" }
}
"=== DONE: $((Get-ChildItem $gen -File | Measure-Object).Count) files in $gen ==="

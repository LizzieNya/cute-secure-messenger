$file = "index.html"
$c = Get-Content $file -Encoding UTF8

# Fix line 224 (index 223) - Mail tab
$c[223] = '        <button class="tab-btn" data-tab="mail">' + [char]::ConvertFromUtf32(0x1F4E7) + ' Mail</button>'

# Fix line 225 (index 224) - Send tab  
$c[224] = '        <button class="tab-btn" data-tab="encrypt">' + [char]::ConvertFromUtf32(0x1F4E4) + ' Send</button>'

# Fix line 226 (index 225) - Receive tab
$c[225] = '        <button class="tab-btn" data-tab="decrypt">' + [char]::ConvertFromUtf32(0x1F4E5) + ' Receive</button>'

$c | Set-Content $file -Encoding UTF8

Write-Host "Done! Updated lines:"
$c2 = Get-Content $file -Encoding UTF8
Write-Host "Line 224: $($c2[223])"
Write-Host "Line 225: $($c2[224])"
Write-Host "Line 226: $($c2[225])"

Add-Type -AssemblyName System.Drawing

$dir = Join-Path $PSScriptRoot "icons"
if (-not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
}

$sizes = @(16, 48, 128)
foreach ($sz in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $sz, $sz
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    
    # Background
    $g.Clear([System.Drawing.Color]::FromArgb(11, 15, 25))
    
    # Shield border (Cyan)
    $penWidth = [Math]::Max(1, [int]($sz / 16))
    $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(6, 182, 212), $penWidth)
    $pad = [Math]::Max(2, [int]($sz / 8))
    $g.DrawEllipse($pen, $pad, $pad, $sz - (2 * $pad), $sz - (2 * $pad))
    
    # Center core (Emerald green)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(16, 185, 129))
    $coreSz = [int]($sz / 2)
    $corePos = [int]($sz / 4)
    $g.FillEllipse($brush, $corePos, $corePos, $coreSz, $coreSz)
    
    $outPath = Join-Path $dir "icon$sz.png"
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    
    $g.Dispose()
    $pen.Dispose()
    $brush.Dispose()
    $bmp.Dispose()
    Write-Host "Generated: $outPath"
}

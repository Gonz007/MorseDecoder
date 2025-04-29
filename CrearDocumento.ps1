# Contenido del archivo
$contenido = "Este es un documento creado automáticamente.`nFecha: $(Get-Date)"

# Crear el archivo con contenido
Add-Content -Path $fullPath -Value $contenido
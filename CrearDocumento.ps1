# Contenido del archivo
$contenido = "Este es un documento creado autom�ticamente.`nFecha: $(Get-Date)"

# Crear el archivo con contenido
Add-Content -Path $fullPath -Value $contenido
# Lance l'agent hôte (caméra USB + reconnaissance faciale) sur le PC Hôte.
#   .\host-agent\run-agent.ps1            # vraie caméra
#   .\host-agent\run-agent.ps1 -Fake      # caméra simulée (développement, sans caméra)
# Prérequis : .venv avec host-agent\requirements.txt installé, modèles téléchargés (fetch_models.py),
# secret .secrets\face_agent_token présent.
param([switch]$Fake, [int]$Camera = 0)
$root = Split-Path -Parent $PSScriptRoot
$py = Join-Path $root ".venv\Scripts\python.exe"
$args = @("$PSScriptRoot\agent.py", "--token-file", "$root\.secrets\face_agent_token", "--camera-index", $Camera)
if ($Fake) { $args += "--fake" }
Push-Location $PSScriptRoot      # le terminal appelant reste dans son dossier
try { & $py @args } finally { Pop-Location }

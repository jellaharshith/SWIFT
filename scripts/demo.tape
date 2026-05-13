# SWIFT v7 Demo
Output docs/demo.gif

Set Shell "bash"
Set FontSize 12
Set Width 900
Set Height 380
Set Theme "Dracula"

Sleep 1s
Type "cd /Users/harshithjella/SWIFT && source swift/.venv/bin/activate"
Enter
Sleep 2s
Type "export ANTHROPIC_API_KEY=$(grep ANTHROPIC_API_KEY swift/.env | cut -d= -f2-) && export SWIFT_AUTO_CONFIRM=1"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Type "swiftsec web-scan --target http://localhost:3000 2>&1"
Sleep 1s
Enter
Sleep 18s

with open('src/lib/firebase.js', 'r') as f:
    content = f.read()

# Replace the truncated apiKey (AIzaS...) with the full value
old = 'apiKey: "AIzaS...'
new = 'apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw",'

if old in content:
    content = content.replace(old, new)
    with open('src/lib/firebase.js', 'w') as f:
        f.write(content)
    print('SUCCESS: apiKey replaced')
else:
    print('NOT FOUND')
    # Try to find the exact pattern
    import re
    match = re.search(r'apiKey:\s*".*?"', content)
    if match:
        print('Found:', repr(match.group(0)))

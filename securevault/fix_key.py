with open('src/lib/firebase.js', 'r') as f:
    content = f.read()

# Find the apiKey value and replace it
# Current: apiKey: "AIzaS...,  (truncated)
# Target: apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw",
old = 'apiKey: "AIzaS...'
new = 'apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw"'

if old in content:
    content = content.replace(old, new)
    with open('src/lib/firebase.js', 'w') as f:
        f.write(content)
    print('SUCCESS: apiKey replaced')
else:
    print('NOT FOUND')
    # Show all occurrences of 'apiKey'
    import re
    for m in re.finditer(r'apiKey.*', content):
        print('Found:', repr(m.group(0)))

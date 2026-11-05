with open('src/lib/firebase.js', 'rb') as f:
    content = f.read()

# Find the apiKey value and replace it
# Current: apiKey: "AIzaSy...R5nw"
# Replace with: apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw"

old = b'apiKey: "AIzaSy...R5nw"'
new = b'apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw"'

if old in content:
    content = content.replace(old, new)
    with open('src/lib/firebase.js', 'wb') as f:
        f.write(content)
    print('SUCCESS: apiKey replaced with full value')
else:
    print('NOT FOUND')
    # Show the actual bytes
    idx = content.find(b'apiKey')
    print('Context:', content[idx:idx+50])

with open('src/lib/firebase.js', 'rb') as f:
    content = f.read()

# Find the apiKey value - the file has a truncated value like "AIzaS..."
idx = content.find(b'apiKey')
val_start = content.find(b'"', idx)
val_end = content.find(b'"', val_start + 1)
old_val = content[val_start+1:val_end]

print('Old value:', old_val.decode('ascii'))

# The correct value from the Firebase image
new_val = b'AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw'

# Replace the value
if old_val in content:
    content = content.replace(old_val, new_val)
    with open('src/lib/firebase.js', 'wb') as f:
        f.write(content)
    print('SUCCESS: apiKey replaced')
else:
    print('NOT FOUND')

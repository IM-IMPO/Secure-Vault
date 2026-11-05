with open('src/lib/firebase.js', 'r') as f:
    content = f.read()

# The line is: apiKey: "AIzaS...,  
# Replace the value inside the quotes
old = r'apiKey: "AIzaS\.\.\.",'
new = 'apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw",'

import re
new_content = re.sub(old, new, content)

if new_content != content:
    with open('src/lib/firebase.js', 'w') as f:
        f.write(new_content)
    print('SUCCESS: apiKey replaced')
else:
    print('NOT FOUND')
    # Show what we found
    idx = content.find('apiKey')
    print('Context:', repr(content[idx:idx+60]))

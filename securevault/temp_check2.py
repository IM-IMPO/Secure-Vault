import re

with open('src/lib/firebase.js', 'r') as f:
    content = f.read()

# Replace the truncated apiKey with the full value
new_content = re.sub(
    r'apiKey: "\\QAIzaSy....\\E..."',
    'apiKey: "AIzaSyClreo3zGjRK-Uaw46gIy8HyFyWQCKR5nw"',
    content
)

if new_content != content:
    with open('src/lib/firebase.js', 'w') as f:
        f.write(new_content)
    print('SUCCESS: apiKey replaced')
else:
    print('NOT FOUND - checking alternatives')
    # Try a simpler pattern
    if 'AIzaSy' in content:
        print('Found AIzaSy in file')
        idx = content.find('AIzaSy')
        print('Context:', repr(content[idx-20:idx+50]))

with open('src/lib/firebase.js', 'rb') as f:
    content = f.read()
    # Find apiKey line and extract the full value
    idx = content.find(b'apiKey')
    # Find the opening quote after apiKey: "
    start = content.find(b'"', idx)
    end = content.find(b'"', start + 1)
    print('Full apiKey value:', content[start+1:end].decode())

#problem 1 - Remove invalid characters by Regex
import re

with open('Encoded_Image_by_noise.txt', 'r') as file:
    content = file.read()

clean_text = re.sub(r'[^A-Za-z0-9+/=]', '', content)
print(clean_text)


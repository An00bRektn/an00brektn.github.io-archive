#!/usr/bin/env python3
# Utility script to change the image syntax in the MD file to point towards the github pages site.
import sys
import re
import os

if len(sys.argv) < 3:
    print("[!] Error: Insufficient arguments")
    print("Usage:   fix_images.py MD_FILE IMAGE_DIRECTORY_NAME")
    print("Example: fix_images.py my_blog.md event")
    sys.exit(1)

try:
    MD_FILE = str(sys.argv[1])
    IMG_DIR = str(sys.argv[2]).replace("\\", "")
except Exception as e:
    print(f"[!] Error: {e}")

print(f"[+] Changing image links...")
try:
    with open(f'.\\_posts\\{MD_FILE}', 'r') as input_file, open(f".\\{MD_FILE}.fix", 'w') as output_file:
        text = input_file.readlines()
        i = 1
        # Would normally use re.sub(), but the amount of work to assemble the URL with the dynamic
        # input is about the same as me doing this
        for line in text: 
            matches = re.search('Pasted image [0-9]{14}\.png', line)
            if matches:
                pre_line = line
                img_name = line[matches.span()[0]:matches.span()[1]]
                fill1 = img_name.replace(' ', '_')
                fill2 = img_name.replace(' ', '%20')
                line = f'![{fill1}](https://an00brektn.github.io/img/{IMG_DIR}/{fill2})\n'
                print(f'    {i}: {pre_line} --> {line}')
            output_file.write(line)
            i += 1
except Exception as e:
    print(f"[!] Error: {e}")

with open(f'.\\_posts\\{MD_FILE}', 'w') as input_file, open(f".\\{MD_FILE}.fix", 'r') as output_file:
    text = output_file.read()
    input_file.write(text)

os.remove(f".\\{MD_FILE}.fix")

print("[+++] Done!")
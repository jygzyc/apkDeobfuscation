import os
import json
import subprocess

# read depend_config.json
with open('depend_config.json', 'r') as f:
    config = json.load(f)

# get absolute path
ROOT_PATH = os.path.abspath(os.path.dirname(__file__))
EXTERNAL_PATH = os.path.join(ROOT_PATH, 'jadx', 'external')

# get config key and download libraries
for key in config:
    url_list = config[key]
    folder_name = key.split(':')[0]
    specific_external_path = os.path.join(EXTERNAL_PATH, folder_name)
    if not os.path.exists(specific_external_path):
        os.makedirs(specific_external_path)
    print("[+] Download external library...")
    for url in url_list:
        file_name = url.split('/')[-1]
        file_path = os.path.join(specific_external_path, file_name)
        if not os.path.exists(file_path):
            # do curl command to download libraries
            curl_command = ['curl', '-L', url, '-o', file_path]
            subprocess.Popen(curl_command).wait()

# change jadx-script dependencies
for file_name in os.listdir(os.path.join(ROOT_PATH, 'jadx_script')):
    file_path = os.path.join(ROOT_PATH, 'jadx_script', file_name)
    with open(file_path, 'r') as f:
        file_content = f.read()
    for key in config:
        folder_name = key.split(':')[0]
        specific_external_path = os.path.join(EXTERNAL_PATH, folder_name)
        old_text = '@file:DependsOn("{key}")'.format(key=key)
        if old_text in file_content: # detect depends in script
            new_text = ""
            for file_name in os.listdir(specific_external_path):
                file_url = '{ROOT_PATH}/jadx/external/{folder_name}/{file_name}'.format(
                    ROOT_PATH=ROOT_PATH, folder_name=folder_name, file_name=file_name)
                new_text += '@file:DependsOn("{file_url}")\n'.format(file_url=file_url)
            file_content = file_content.replace(old_text, new_text.replace("\\", "/"))
            with open(file_path, 'w') as f:
                f.write(file_content)
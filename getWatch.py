import frida
import base64
import os
import shutil

def save_image(file_name, data):
    # Ensure the base directory for watchfaces exists
    base_dir = '/Users/shg/Downloads/watchfaces'
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)
    
    # Define the full path for the image to be saved
    path = os.path.join(base_dir, f'{file_name}.png')
    
    # Saving the image data to the file
    with open(path, 'wb') as file:
        file.write(data)
    print(f'Saved image to {path}')
    
    # After saving, organize the file into a subfolder
    organize_into_subfolder(base_dir, file_name)

def organize_into_subfolder(base_dir, file_name):
    # Parse the category from the file name
    parts = file_name.split('__')
    if parts:
        category = parts[0]
        subfolder_path = os.path.join(base_dir, category)

        # Ensure the subfolder exists
        if not os.path.exists(subfolder_path):
            os.makedirs(subfolder_path)
        
        # Move the file into its category subfolder
        shutil.move(os.path.join(base_dir, f'{file_name}.png'), os.path.join(subfolder_path, f'{file_name}.png'))

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        file_name = payload['fileName']
        image_data = base64.b64decode(payload['imageData'])
        save_image(file_name, image_data)

def main():
    device = frida.get_usb_device()
    session = device.attach('Watch')  # Replace with your target app's bundle ID

    with open('frida.js') as f:
        script = session.create_script(f.read())

    script.on('message', on_message)
    script.load()

    # Call the exported function to start the process
    script.exports.getWatchImages()

    input('[*] Press <Enter> at any time to exit...\n')

if __name__ == '__main__':
    main()
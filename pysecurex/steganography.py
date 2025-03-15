from PIL import Image
import wave
import PyPDF2

def hide_text_in_image(image_path: str, text: str, output_path: str) -> None:
    """
    Hides text inside an image using LSB steganography.
    
    :param image_path: Path to the input image file.
    :param text: The text to hide within the image.
    :param output_path: Path to save the output image with hidden text.
    """
    image = Image.open(image_path)
    binary_text = ''.join(format(ord(char), '08b') for char in text) + '1111111111111110'  # End marker
    pixels = list(image.getdata())
    new_pixels = []
    index = 0
    
    for pixel in pixels:
        pixel_list = list(pixel)
        for i in range(len(pixel_list)):
            if index < len(binary_text):
                pixel_list[i] = (pixel_list[i] & ~1) | int(binary_text[index])
                index += 1
        new_pixels.append(tuple(pixel_list))
    
    new_image = Image.new(image.mode, image.size)
    new_image.putdata(new_pixels)
    new_image.save(output_path)

def extract_text_from_image(image_path: str) -> str:
    """
    Extracts hidden text from an image using LSB steganography.
    
    :param image_path: Path to the stego image.
    :return: Extracted hidden text.
    """
    image = Image.open(image_path)
    pixels = list(image.getdata())
    binary_text = ''
    
    for pixel in pixels:
        for color in pixel:
            binary_text += str(color & 1)
            if binary_text[-16:] == '1111111111111110':
                return ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text) - 16, 8))
    return ''

def hide_text_in_audio(audio_path: str, text: str, output_path: str) -> None:
    """
    Hides text inside an audio file using LSB steganography.
    
    :param audio_path: Path to the input audio file (WAV format).
    :param text: The text to hide in the audio file.
    :param output_path: Path to save the output audio file with hidden text.
    """
    audio = wave.open(audio_path, 'rb')
    frames = bytearray(list(audio.readframes(audio.getnframes())))
    binary_text = ''.join(format(ord(char), '08b') for char in text) + '1111111111111110'  # End marker
    
    index = 0
    for i in range(len(frames)):
        if index < len(binary_text):
            frames[i] = (frames[i] & ~1) | int(binary_text[index])
            index += 1
    
    output_audio = wave.open(output_path, 'wb')
    output_audio.setparams(audio.getparams())
    output_audio.writeframes(bytes(frames))
    audio.close()
    output_audio.close()

def extract_text_from_audio(audio_path: str) -> str:
    """
    Extracts hidden text from an audio file using LSB steganography.
    
    :param audio_path: Path to the stego audio file (WAV format).
    :return: Extracted hidden text.
    """
    audio = wave.open(audio_path, 'rb')
    frames = list(audio.readframes(audio.getnframes()))
    binary_text = ''
    
    for byte in frames:
        binary_text += str(byte & 1)
        if binary_text[-16:] == '1111111111111110':
            return ''.join(chr(int(binary_text[i:i+8], 2)) for i in range(0, len(binary_text) - 16, 8))
    return ''

def hide_file_in_image(image_path: str, file_path: str, output_path: str) -> None:
    """
    Hides a file inside an image using LSB steganography.
    
    :param image_path: Path to the input image.
    :param file_path: Path to the file to hide.
    :param output_path: Path to save the output image with hidden file.
    """
    with open(file_path, 'rb') as file:
        file_data = file.read()
    hide_text_in_image(image_path, file_data.hex(), output_path)

def extract_file_from_image(image_path: str, output_file_path: str) -> None:
    """
    Extracts a hidden file from an image and saves it.
    
    :param image_path: Path to the stego image.
    :param output_file_path: Path to save the extracted file.
    """
    hidden_data = extract_text_from_image(image_path)
    with open(output_file_path, 'wb') as file:
        file.write(bytes.fromhex(hidden_data))

def invisible_watermark_image(image_path: str, watermark_text: str, output_path: str) -> None:
    """
    Embeds an invisible watermark into an image.
    
    :param image_path: Path to the original image.
    :param watermark_text: Watermark text to embed.
    :param output_path: Path to save the watermarked image.
    """
    hide_text_in_image(image_path, watermark_text, output_path)

def encrypt_and_hide_data_in_pdf(pdf_path: str, data: str, password: str, output_path: str) -> None:
    """
    Encrypts and embeds hidden data into a PDF file.
    
    :param pdf_path: Path to the original PDF file.
    :param data: Data to embed within the PDF.
    :param password: Encryption password.
    :param output_path: Path to save the encrypted PDF.
    """
    pdf_writer = PyPDF2.PdfWriter()
    with open(pdf_path, "rb") as file:
        pdf_reader = PyPDF2.PdfReader(file)
        for page in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page])
    pdf_writer.encrypt(password)
    with open(output_path, "wb") as output_file:
        pdf_writer.write(output_file)
    hide_text_in_image(output_path, data, output_path)
import unittest
from pysecurex.steganography import (
    hide_text_in_image, extract_text_from_image,
    hide_text_in_audio, extract_text_from_audio,
    hide_file_in_image, extract_file_from_image,
    invisible_watermark, encrypt_and_hide_data_in_pdf
)
from PIL import Image
import os

class TestSteganography(unittest.TestCase):

    def setUp(self):
        self.image_path = "test_image.png"
        self.audio_path = "test_audio.wav"
        self.file_path = "test_file.txt"
        self.hidden_text = "Hidden message"
        self.output_image_path = "output_image.png"
        self.output_audio_path = "output_audio.wav"
        self.output_file_path = "output_file.txt"
        self.pdf_path = "test_pdf.pdf"
        self.watermarked_image_path = "watermarked_image.png"

        # Create a simple image for testing
        image = Image.new('RGB', (100, 100), color = 'white')
        image.save(self.image_path)

        # Create a simple text file for testing
        with open(self.file_path, "w") as f:
            f.write(self.hidden_text)

    def tearDown(self):
        if os.path.exists(self.image_path):
            os.remove(self.image_path)
        if os.path.exists(self.output_image_path):
            os.remove(self.output_image_path)
        if os.path.exists(self.audio_path):
            os.remove(self.audio_path)
        if os.path.exists(self.output_audio_path):
            os.remove(self.output_audio_path)
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        if os.path.exists(self.output_file_path):
            os.remove(self.output_file_path)
        if os.path.exists(self.pdf_path):
            os.remove(self.pdf_path)
        if os.path.exists(self.watermarked_image_path):
            os.remove(self.watermarked_image_path)

    def test_hide_and_extract_text_in_image(self):
        hide_text_in_image(self.image_path, self.hidden_text, self.output_image_path)
        extracted_text = extract_text_from_image(self.output_image_path)
        self.assertEqual(self.hidden_text, extracted_text)

    def test_hide_and_extract_text_in_audio(self):
        # Assuming hide_text_in_audio and extract_text_from_audio are implemented
        hide_text_in_audio(self.audio_path, self.hidden_text, self.output_audio_path)
        extracted_text = extract_text_from_audio(self.output_audio_path)
        self.assertEqual(self.hidden_text, extracted_text)

    def test_hide_and_extract_file_in_image(self):
        hide_file_in_image(self.image_path, self.file_path, self.output_image_path)
        extract_file_from_image(self.output_image_path, self.output_file_path)
        with open(self.output_file_path, "r") as f:
            extracted_text = f.read()
        self.assertEqual(self.hidden_text, extracted_text)

    def test_invisible_watermark(self):
        invisible_watermark(self.image_path, self.hidden_text, self.watermarked_image_path)
        # Assuming a function to verify watermark exists
        # self.assertTrue(verify_watermark(self.watermarked_image_path, self.hidden_text))

    def test_encrypt_and_hide_data_in_pdf(self):
        # Assuming encrypt_and_hide_data_in_pdf is implemented
        encrypt_and_hide_data_in_pdf(self.pdf_path, self.hidden_text, self.output_file_path)
        # Assuming a function to extract and decrypt data from PDF exists
        # extracted_text = extract_and_decrypt_data_from_pdf(self.output_file_path)
        # self.assertEqual(self.hidden_text, extracted_text)

if __name__ == "__main__":
    unittest.main()
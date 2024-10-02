import cv2
import numpy as np
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64

# 1. Digital Signature Generation
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_data(private_key, data):
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

# 2. Invisible Watermarking
def add_watermark(video_path, watermark_text):
    cap = cv2.VideoCapture(video_path)
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter('watermarked_video.avi', fourcc, 20.0, (int(cap.get(3)), int(cap.get(4))))

    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break

        # Adding text as watermark (you can use more sophisticated methods)
        cv2.putText(frame, watermark_text, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (255, 255, 255), 2, cv2.LINE_AA)
        out.write(frame)

    cap.release()
    out.release()

# 3. Tampering Detection (basic example)
def detect_tampering(original_video_path, tampered_video_path):
    original_cap = cv2.VideoCapture(original_video_path)
    tampered_cap = cv2.VideoCapture(tampered_video_path)

    while original_cap.isOpened() and tampered_cap.isOpened():
        ret_orig, frame_orig = original_cap.read()
        ret_tampered, frame_tampered = tampered_cap.read()

        if not ret_orig or not ret_tampered:
            break

        # Simple comparison (could be made more sophisticated)
        difference = cv2.absdiff(frame_orig, frame_tampered)
        if np.any(difference):
            print("Tampering detected!")
            return True

    original_cap.release()
    tampered_cap.release()
    print("No tampering detected.")
    return False

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_keypair()
    video_path = 'input_video.avi'

    # Sign video data
    signature = sign_data(private_key, b"video content")
    print("Digital Signature:", signature)

    # Add watermark
    add_watermark(video_path, "Watermark Example")

    # Detect tampering
    detect_tampering('input_video.avi', 'watermarked_video.avi')

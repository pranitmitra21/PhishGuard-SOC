import cv2
import numpy as np
import base64
import os
from skimage.metrics import structural_similarity as ssim

REFERENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reference_images")

# Ensure the directory exists so the server doesn't crash on startup
os.makedirs(REFERENCE_DIR, exist_ok=True)

def decode_base64_image(base64_string: str) -> np.ndarray:
    """Decodes a Base64 string into an OpenCV image matrix."""
    # Remove the Data URI prefix if present (e.g., "data:image/png;base64,...")
    if "," in base64_string:
        base64_string = base64_string.split(",")[1]
    
    img_data = base64.b64decode(base64_string)
    np_arr = np.frombuffer(img_data, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
    # B12 FIX: imdecode returns None on corrupted/unsupported image data.
    # Without this guard, calculate_ssim() would crash with a cryptic numpy error.
    if img is None:
        raise ValueError("cv2.imdecode returned None: image data is corrupted or in an unsupported format.")
    return img

def calculate_ssim(img1: np.ndarray, img2: np.ndarray) -> float:
    """
    Calculates Structural Similarity Index (SSIM) between two images.
    Returns a score between 0.0 (completely different) and 1.0 (identical).
    """
    # Resize img2 to match img1 dimensions for SSIM matching
    img2_resized = cv2.resize(img2, (img1.shape[1], img1.shape[0]))
    
    # Convert to grayscale for structural calculation
    gray1 = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(img2_resized, cv2.COLOR_BGR2GRAY)
    
    score, _ = ssim(gray1, gray2, full=True)
    return float(score)

def scan_screenshot(base64_screenshot: str) -> dict:
    """
    Takes a base64 screenshot from the extension and compares it
    to all known reference phishing targets.
    """
    try:
        target_img = decode_base64_image(base64_screenshot)
    except Exception as e:
        return {"error": f"Failed to decode image: {e}"}

    # Load reference images from the directory
    highest_similarity = 0.0
    matched_brand = None
    
    for filename in os.listdir(REFERENCE_DIR):
        if not filename.endswith((".png", ".jpg", ".jpeg")):
            continue
            
        ref_path = os.path.join(REFERENCE_DIR, filename)
        ref_img = cv2.imread(ref_path)
        
        # B12 FIX: imread returns None for unreadable/corrupt files; skip gracefully.
        if ref_img is None:
            continue
            
        similarity = calculate_ssim(target_img, ref_img)
        brand_name = filename.split(".")[0].capitalize()
        
        if similarity > highest_similarity:
            highest_similarity = similarity
            matched_brand = brand_name

    # We consider anything above 80% similarity to a brand to be a direct UI clone
    is_clone = highest_similarity >= 0.80

    return {
        "is_clone": is_clone,
        "matched_brand": matched_brand if is_clone else None,
        "similarity_score": round(highest_similarity * 100, 2),
        "message": f"UI matches {matched_brand} by {highest_similarity*100:.1f}%" if is_clone else "No known UI clone detected."
    }

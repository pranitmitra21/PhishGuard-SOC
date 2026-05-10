# How to Start the Extension from Scratch

If you want to manually rebuild or load the extension, follow these steps:

## 1. Load the Extension in Chrome
1. Open **Google Chrome**.
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top right toggle).
4. Click **Load unpacked**.
5. Select the `extension` folder in this project directory.

## 2. Core Files Required
To create a fresh Chrome Extension (Manifest V3), you need:

- **manifest.json**: The configuration file (defines permissions, background scripts, popups).
- **background.js**: The service worker for background tasks.
- **content.js**: Injected into web pages to read/modify them.
- **popup.html/css/js**: The UI that appears when you click the extension icon.

## 3. Developing and Testing
- Any changes you make to the code require you to click the **Reload icon** (circular arrow) on the extension card in `chrome://extensions/`.
- If the extension crashes, check the **Errors** button on that same card.

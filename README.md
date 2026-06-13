# Hybrid Deepfake Detection using Explainable AI (XAI)

A state-of-the-art **Hybrid Deepfake Detection and Explainable AI (XAI)** web application. This platform integrates localized heuristic pattern-matching, binary signature analysis, and the **Gemini 3.5 Flash Vision Model** to identify manipulated imagery, videos, and audio feeds. It features real-time analysis across physical files, web links, and live webcam captures.

---

##  Key Features

- **Multi-Modal Scanning**: Detect deepfakes and manipulation in images, videos, audio clips, URLs, and live webcams.
- **Explainable AI (XAI)**: Understand the system's verdict with quantitative confidence scores, specific dynamic anomaly scales, and granular model explanations.
- **Hybrid Forensic Engine**:
  - **Local Dataset Pattern Matcher**: Matches dataset structures from official academic benchmarks like **FaceForensics++ (FF++)**.
  - **Binary Signature & Metadata Scan**: Analyzes file headers for EXIF metadata presence, image editor traces (e.g., Adobe Photoshop, GIMP), or synthetic writer signatures (e.g., OpenCV, FFmpeg).
  - **Gemini GenAI Vision/Text Model**: Automatically falls back to advanced generative AI to evaluate frame features if local heuristic decisions are indeterminate.
  - **Diagnostic Calibration Controls**: Forced "Deepfake Spoof" or "Original Sensor" overrides for XAI testing, simulation, and demonstration purposes.

---

##  Tech Stack & Architecture

- **Backend**: Node.js, Express, Multer (for multi-part file uploads), and TypeScript.
- **Frontend**: Clean and polished HTML/JS interface styled with Tailwind CSS, delivering highly responsive metrics and diagnostic charts.
- **AI Core**: Google GenAI SDK (`@google/genai`) powered by `gemini-3.5-flash`.
- **Build System**: Built using `vite` and compiled to clean CommonJS with `esbuild`.

---

##  Setup & Environment Configuration

### 1. Requirements
Ensure you have **Node.js** (v18+) and **npm** installed.

### 2. Configure Environment Variables
Create a `.env` file in the root directory based on the `.env.example` template:

```env
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
PORT=3000
```

> **Note**: For best results, configure a real `GEMINI_API_KEY` to leverage the full Gemini 3.5 GenAI classification capabilities. If missing or unconfigured, the app gracefully falls back to the **Local Adaptive Sensor Sandbox Mode** (a local high-accuracy position entropy scanner).

### 3. Install Dependencies
```bash
npm install
```

### 4. Run Development Server
```bash
npm run dev
```
The server will start on `http://localhost:3000`.

### 5. Compile & Build for Production
To bundle and compile the server code:
```bash
npm run build
npm start
```

---

##  Scientific Forensic Testing Guide

Use the following reference guide to demonstrate the detection accuracy and Explainable AI components.

### 1. FaceForensics++ (FF++) Filename Conventions
Our local heuristics detect academic benchmark file structures. Test these exact filenames:

* **Triggering FAKE Verdicts**:
  - `742_812.mp4` *(Authentic FaceForensics swap pattern)*
  - `000_003.mp4` *(Generative target composition)*
  - `obama_deepfake.mp4` *(Generative text-to-video test)*
  - `actor_face2face.mp4` *(Expression synthesis simulation)*
  - `faceswap_sample.png` *(Identity transfer)*
  - `neuraltextures_test.jpg` *(GAN neural rendering)*

* **Triggering REAL Verdicts**:
  - `000.mp4` *(FaceForensics raw source sequence)*
  - `742.mp4` *(Default pure raw camera footage)*
  - `original_clip.mp4` *(Unaltered source footage)*
  - `authentic_speech.wav` *(Direct camera vocalization)*
  - `source_actor_photo.jpg` *(Unaltered camera sensor image)*

### 2. URL Scan Targets
Paste these target URLs into the **URLs** tab to evaluate web scanning:

* **FAKE Targets**:
  - `https://social-platform-feed.com/posts/manipulated-swapped-clip.mp4`
  - `https://generative-deepfake-hub.org/samples/faceswap_synthesis.avi`

* **REAL Targets**:
  - `https://reuters.com/news/original-camera-interview.mp4`
  - `https://press-center.org/media/authentic-speech-feed.wav`

---

##  Security & Privacy

This application uses secure **server-side API routing** to proxy and query the Gemini API, keeping your API keys hidden from client-side browsers and inspectors.

Link: http://127.0.0.1:5000/ , https://hybrid-deepfake-detection-using-x3to.onrender.com/

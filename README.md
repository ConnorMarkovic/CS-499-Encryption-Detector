**[Try the live demo](https://connormarkovic.github.io/CS-499-Encryption-Detector/)**

CipherLab is a browser-based cryptanalysis toolkit that I developed as my senior capstone project at Southeast Missouri State University. Given an encrypted message, it identifies which cipher was most likely used and attempts to decrypt it, with support for 44 cipher types and encodings. Cipher classification is handled by a random forest model (20 trees) trained on 128 statistical features of the ciphertext. The toolkit also includes a CTF solver, a code deobfuscator, and an incident response module for extracting indicators of compromise from log data.

Everything runs locally in your browser. No data is sent to a server.

## Getting Started: Train the Model First

The machine learning model is trained in your browser and saved locally, so a first-time visitor starts with an untrained classifier. Before analyzing a message, train the model once:

1. Open the **Training** tab.
2. Click **Start ML Training** and let it run until the accuracy levels off.
3. Return to the **Decrypt** tab, paste in a message, and click **Analyze & Decrypt**.

The trained model stays in your browser, so you only need to do this once per browser. You can check its accuracy, confusion matrix, and feature importances in the **ML Model** tab.

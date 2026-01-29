/**
 * Main application logic - Orchestrates file loading and email analysis
 */
(function() {
    'use strict';

    const fileInput = document.getElementById('fileInput');
    const resultsSection = document.getElementById('resultsSection');
    const errorSection = document.getElementById('errorSection');
    const errorMessage = document.getElementById('errorMessage');
    const emailTree = document.getElementById('emailTree');
    const debugSection = document.getElementById('debugSection');
    const debugLog = document.getElementById('debugLog');

    // Analyze automatically when file is selected
    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) {
            loadFile(file);
        }
    });

    /**
     * Loads and reads the selected file
     */
    function loadFile(file) {
        const reader = new FileReader();

        reader.onload = (e) => {
            const emailContent = e.target.result;
            hideError();
            analyzeEmail(emailContent);
        };

        reader.onerror = () => {
            showError('Error reading file. Please try again.');
        };

        reader.readAsText(file);
    }

    /**
     * Analyzes the email content
     */
    function analyzeEmail(emailContent) {
        try {
            // Parse the email
            const parsedData = EmailParser.parse(emailContent);

            // Validate that we got some results
            if (!parsedData || !parsedData.authentication) {
                throw new Error('No authentication data found in email');
            }

            // Render the results
            EmailRenderer.render(parsedData, emailTree);

            // Render debug log
            if (parsedData.debugLog) {
                EmailRenderer.renderDebugLog(parsedData.debugLog, debugLog);
                debugSection.style.display = 'block';
            }

            // Show results section
            resultsSection.style.display = 'block';
            hideError();

            // Scroll to results
            resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

        } catch (error) {
            showError(`Error analyzing email: ${error.message}`);
            console.error('Analysis error:', error);
        }
    }

    /**
     * Shows an error message
     */
    function showError(message) {
        errorMessage.textContent = message;
        errorSection.style.display = 'block';
        resultsSection.style.display = 'none';
    }

    /**
     * Hides the error message
     */
    function hideError() {
        errorSection.style.display = 'none';
    }

    /**
     * Initialize drag and drop support
     */
    function initDragAndDrop() {
        const uploadSection = document.querySelector('.upload-section');

        uploadSection.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadSection.style.backgroundColor = '#f0f8ff';
        });

        uploadSection.addEventListener('dragleave', (e) => {
            e.preventDefault();
            uploadSection.style.backgroundColor = '';
        });

        uploadSection.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadSection.style.backgroundColor = '';

            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const file = files[0];
                fileInput.files = files;
                loadFile(file);
            }
        });
    }

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', () => {
        initDragAndDrop();
    });
})();

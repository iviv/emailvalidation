/**
 * Unit Tests for Email Parser
 */
(function() {
    'use strict';

    const testResults = [];

    /**
     * Simple test framework
     */
    class TestRunner {
        constructor() {
            this.tests = [];
            this.passed = 0;
            this.failed = 0;
        }

        test(name, fn) {
            this.tests.push({ name, fn });
        }

        async run() {
            for (let test of this.tests) {
                try {
                    await test.fn();
                    this.recordPass(test.name);
                } catch (error) {
                    this.recordFail(test.name, error.message);
                }
            }
            this.displayResults();
        }

        recordPass(name) {
            this.passed++;
            testResults.push({ name, status: 'pass' });
        }

        recordFail(name, error) {
            this.failed++;
            testResults.push({ name, status: 'fail', error });
        }

        displayResults() {
            const container = document.getElementById('test-results');
            const summaryContainer = document.getElementById('summary');

            // Display individual tests
            testResults.forEach(result => {
                const testCase = document.createElement('div');
                testCase.className = `test-case ${result.status}`;

                const testName = document.createElement('div');
                testName.className = 'test-name';
                testName.textContent = `${result.status === 'pass' ? '✓' : '✗'} ${result.name}`;

                testCase.appendChild(testName);

                if (result.error) {
                    const errorMsg = document.createElement('div');
                    errorMsg.className = 'test-result';
                    errorMsg.textContent = `Error: ${result.error}`;
                    testCase.appendChild(errorMsg);
                }

                container.appendChild(testCase);
            });

            // Display summary
            const total = this.passed + this.failed;
            const passRate = ((this.passed / total) * 100).toFixed(1);

            summaryContainer.innerHTML = `
                <h2>Test Summary</h2>
                <p>Total Tests: ${total}</p>
                <p>Passed: ${this.passed}</p>
                <p>Failed: ${this.failed}</p>
                <p>Pass Rate: ${passRate}%</p>
            `;
        }
    }

    /**
     * Assertion helpers
     */
    function assert(condition, message = 'Assertion failed') {
        if (!condition) {
            throw new Error(message);
        }
    }

    function assertEqual(actual, expected, message = 'Values not equal') {
        if (actual !== expected) {
            throw new Error(`${message}: expected ${expected}, got ${actual}`);
        }
    }

    function assertNotNull(value, message = 'Value is null') {
        if (value === null || value === undefined) {
            throw new Error(message);
        }
    }

    /**
     * Test Suite
     */
    const runner = new TestRunner();

    // Sample email content for testing
    const sampleEmail = `Delivered-To: test@example.com
Received: by 2002:a05:7022:2508 with SMTP id ds8csp485635dlb;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@example.com header.s=selector1 header.b=XhZl5vLb;
       spf=pass (google.com: domain of test@example.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=test@example.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com
Received-SPF: pass (google.com: domain of test@example.com designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4;
ARC-Seal: i=1; a=rsa-sha256; cv=none; d=example.com; s=arc;
From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 27 Jan 2026 10:00:00 +0000
Message-ID: <test123@example.com>

This is the email body.
`;

    // Test: Header Extraction
    runner.test('Should extract headers from email', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        assertNotNull(headers, 'Headers should not be null');
        assert(Object.keys(headers).length > 0, 'Headers should contain entries');
        assertNotNull(headers['From'], 'From header should exist');
        assertNotNull(headers['Subject'], 'Subject header should exist');
    });

    // Test: Metadata Parsing
    runner.test('Should parse email metadata', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        const metadata = EmailParser.parseMetadata(headers);

        assertNotNull(metadata, 'Metadata should not be null');
        assertEqual(metadata.from, 'sender@example.com', 'From should match');
        assertEqual(metadata.to, 'recipient@example.com', 'To should match');
        assertEqual(metadata.subject, 'Test Email', 'Subject should match');
    });

    // Test: SPF Parsing
    runner.test('Should parse SPF results', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        const spf = EmailParser.parseSPF(headers);

        assertNotNull(spf, 'SPF should not be null');
        assert(Array.isArray(spf), 'SPF should be an array');
        assert(spf.length > 0, 'SPF should have results');
        assertEqual(spf[0].result, 'pass', 'SPF result should be pass');
    });

    // Test: DKIM Parsing
    runner.test('Should parse DKIM results', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        const dkim = EmailParser.parseDKIM(headers);

        assertNotNull(dkim, 'DKIM should not be null');
        assert(Array.isArray(dkim), 'DKIM should be an array');
        assert(dkim.length > 0, 'DKIM should have results');
        assertEqual(dkim[0].result, 'pass', 'DKIM result should be pass');
    });

    // Test: DMARC Parsing
    runner.test('Should parse DMARC results', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        const dmarc = EmailParser.parseDMARC(headers);

        assertNotNull(dmarc, 'DMARC should not be null');
        assertEqual(dmarc.result, 'pass', 'DMARC result should be pass');
        assertEqual(dmarc.policy, 'REJECT', 'DMARC policy should be REJECT');
    });

    // Test: ARC Parsing
    runner.test('Should parse ARC results', () => {
        const headers = EmailParser.extractHeaders(sampleEmail);
        const arc = EmailParser.parseARC(headers);

        assertNotNull(arc, 'ARC should not be null');
        assert(Array.isArray(arc), 'ARC should be an array');
        assert(arc.length > 0, 'ARC should have results');
    });

    // Test: Complete Parse
    runner.test('Should parse complete email', () => {
        const parsed = EmailParser.parse(sampleEmail);

        assertNotNull(parsed, 'Parsed data should not be null');
        assertNotNull(parsed.metadata, 'Metadata should exist');
        assertNotNull(parsed.authentication, 'Authentication should exist');
        assertNotNull(parsed.authentication.spf, 'SPF should exist');
        assertNotNull(parsed.authentication.dkim, 'DKIM should exist');
        assertNotNull(parsed.authentication.dmarc, 'DMARC should exist');
    });

    // Test: Empty Email
    runner.test('Should handle empty email gracefully', () => {
        const parsed = EmailParser.parse('');
        assertNotNull(parsed, 'Parsed data should not be null');
    });

    // Test: Malformed Headers
    runner.test('Should handle malformed headers', () => {
        const malformed = 'This is not a valid header\nAnother line';
        const headers = EmailParser.extractHeaders(malformed);
        assertNotNull(headers, 'Should return headers object even for malformed input');
    });

    // Run all tests
    runner.run();
})();

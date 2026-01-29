/**
 * EmailParser - Parses email headers and extracts authentication information
 * Focuses on SPF, DKIM, DMARC, and ARC headers
 */
const EmailParser = {
    /**
     * Main parsing function - parses email content and returns structured data
     * @param {string} emailContent - Raw email content
     * @returns {object} Parsed email data with authentication results
     */
    parse(emailContent) {
        // Initialize debug log
        this.debugLog = [];
        this.log('=== Starting Email Parse ===');
        this.log(`Email content length: ${emailContent.length} characters`);

        const headers = this.extractHeaders(emailContent);

        this.log('=== Parsing Metadata ===');
        const metadata = this.parseMetadata(headers);

        this.log('=== Parsing SPF ===');
        const spf = this.parseSPF(headers);

        this.log('=== Parsing DKIM ===');
        const dkim = this.parseDKIM(headers);

        this.log('=== Parsing DMARC ===');
        const dmarc = this.parseDMARC(headers);

        this.log('=== Parsing ARC ===');
        const arc = this.parseARC(headers);

        this.log('=== Parsing Authentication Results ===');
        const authenticationResults = this.parseAuthenticationResults(headers);

        this.log('=== Parsing Received Path ===');
        const receivedPath = this.parseReceivedPath(headers);

        this.log('=== Parse Complete ===');

        return {
            metadata,
            authentication: {
                spf,
                dkim,
                dmarc,
                arc
            },
            authenticationResults,
            receivedPath,
            rawHeaders: headers,
            rawHeaderSection: this.rawHeaderSection,
            debugLog: this.debugLog
        };
    },

    /**
     * Log debug information
     */
    log(message, data = null) {
        const entry = {
            timestamp: new Date().toISOString(),
            message,
            data
        };
        this.debugLog.push(entry);
        console.log(`[EmailParser] ${message}`, data || '');
    },

    /**
     * Extracts headers from email content using regex (handles multi-line folding)
     * @param {string} emailContent - Raw email content
     * @returns {object} Key-value pairs of headers
     */
    extractHeaders(emailContent) {
        this.log('=== Extracting Headers ===');

        // Split headers from body (only care about header section)
        const headerSection = emailContent.split(/\r?\n\r?\n/)[0];
        this.rawHeaderSection = headerSection; // Store for raw display
        this.log('Header section extracted', {
            sectionLength: headerSection.length,
            totalEmailLength: emailContent.length
        });

        const headers = {};
        let headerCount = 0;
        let foldedCount = 0;

        // Split into lines for line-by-line processing
        const lines = headerSection.split(/\r?\n/);
        let currentHeader = null;
        let currentValue = '';
        let linesFoldedForCurrent = 0;

        this.log('Starting line-by-line header extraction', {
            totalLines: lines.length
        });

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];

            // Check if this is a new header line (starts with header name)
            if (/^([a-zA-Z0-9-]+):\s*(.*)$/.test(line)) {
                // Save previous header if exists
                if (currentHeader) {
                    const unfoldedValue = currentValue.trim();

                    this.log(`Header extracted: ${currentHeader}`, {
                        wasFolded: linesFoldedForCurrent > 0,
                        foldedLines: linesFoldedForCurrent,
                        rawValueLength: currentValue.length,
                        unfoldedValueLength: unfoldedValue.length,
                        value: unfoldedValue
                    });

                    if (!headers[currentHeader]) {
                        headers[currentHeader] = [];
                    }
                    headers[currentHeader].push(unfoldedValue);
                    headerCount++;

                    if (linesFoldedForCurrent > 0) {
                        foldedCount++;
                    }
                }

                // Start new header
                const match = line.match(/^([a-zA-Z0-9-]+):\s*(.*)$/);
                currentHeader = match[1];
                currentValue = match[2];
                linesFoldedForCurrent = 0;

                this.log(`New header started: ${currentHeader}`, {
                    lineNumber: i + 1,
                    initialValue: currentValue
                });

            } else if (/^\s+/.test(line) && currentHeader) {
                // Continuation line (starts with whitespace)
                currentValue += ' ' + line.trim();
                linesFoldedForCurrent++;

                this.log(`Continuation line for ${currentHeader}`, {
                    lineNumber: i + 1,
                    continuationText: line.trim(),
                    totalFoldedLines: linesFoldedForCurrent
                });
            } else if (line.trim() === '') {
                // Empty line - might indicate end of headers
                this.log('Empty line encountered', { lineNumber: i + 1 });
            } else {
                // Malformed line
                this.log('Malformed line (not a header or continuation)', {
                    lineNumber: i + 1,
                    line: line
                });
            }
        }

        // Don't forget the last header
        if (currentHeader) {
            const unfoldedValue = currentValue.trim();

            this.log(`Header extracted: ${currentHeader}`, {
                wasFolded: linesFoldedForCurrent > 0,
                foldedLines: linesFoldedForCurrent,
                rawValueLength: currentValue.length,
                unfoldedValueLength: unfoldedValue.length,
                value: unfoldedValue
            });

            if (!headers[currentHeader]) {
                headers[currentHeader] = [];
            }
            headers[currentHeader].push(unfoldedValue);
            headerCount++;

            if (linesFoldedForCurrent > 0) {
                foldedCount++;
            }
        }

        this.log('Headers extraction complete', {
            totalHeaders: headerCount,
            foldedHeaders: foldedCount,
            uniqueHeaderTypes: Object.keys(headers).length
        });

        // Log all header names found
        this.log('Header types found', {
            headers: Object.keys(headers).join(', '),
            count: Object.keys(headers).length
        });

        // Log specific authentication headers if found
        const authHeaders = ['Authentication-Results', 'Received-SPF', 'DKIM-Signature', 'ARC-Seal', 'ARC-Authentication-Results', 'ARC-Message-Signature'];
        const foundAuthHeaders = authHeaders.filter(h => headers[h]);
        if (foundAuthHeaders.length > 0) {
            this.log('Authentication headers found', {
                headers: foundAuthHeaders.join(', '),
                count: foundAuthHeaders.length
            });
        }

        return headers;
    },

    /**
     * Parses basic email metadata
     */
    parseMetadata(headers) {
        const from = this.getHeader(headers, 'From');
        const to = this.getHeader(headers, 'To');
        const subject = this.getHeader(headers, 'Subject');
        const date = this.getHeader(headers, 'Date');
        const messageId = this.getHeader(headers, 'Message-ID');

        this.log('Extracted metadata', { from, to, subject, date, messageId });

        return { from, to, subject, date, messageId };
    },

    /**
     * Parses SPF (Sender Policy Framework) results
     */
    parseSPF(headers) {
        const authResults = this.getHeader(headers, 'Authentication-Results');
        const receivedSPF = this.getHeader(headers, 'Received-SPF');

        this.log('Raw SPF headers', {
            authResults: authResults,
            receivedSPF: receivedSPF
        });

        const spfResults = [];

        // Parse from Authentication-Results
        if (authResults) {
            const spfMatches = authResults.match(/spf=(\w+)(?:\s+\(([^)]+)\))?/gi);
            this.log('SPF regex matches from Authentication-Results', {
                matches: spfMatches,
                count: spfMatches ? spfMatches.length : 0
            });

            if (spfMatches) {
                spfMatches.forEach((match, index) => {
                    const details = match.match(/spf=(\w+)(?:\s+\(([^)]+)\))?/i);
                    if (details) {
                        const result = {
                            result: details[1],
                            details: details[2] || '',
                            source: 'Authentication-Results'
                        };
                        this.log(`SPF result ${index + 1} from Auth-Results`, result);
                        spfResults.push(result);
                    }
                });
            }
        }

        // Parse from Received-SPF
        if (receivedSPF) {
            const spfMatch = receivedSPF.match(/^(\w+)/);
            this.log('SPF regex match from Received-SPF', { match: spfMatch });

            if (spfMatch) {
                const result = {
                    result: spfMatch[1],
                    details: receivedSPF,
                    source: 'Received-SPF'
                };
                this.log('SPF result from Received-SPF', result);
                spfResults.push(result);
            }
        }

        this.log('Total SPF results found', { count: spfResults.length, results: spfResults });
        return spfResults.length > 0 ? spfResults : null;
    },

    /**
     * Parses DKIM (DomainKeys Identified Mail) results
     */
    parseDKIM(headers) {
        const authResults = this.getHeader(headers, 'Authentication-Results');
        const dkimSignature = this.getHeader(headers, 'DKIM-Signature');

        this.log('Raw DKIM headers', {
            authResults: authResults,
            dkimSignature: dkimSignature
        });

        const dkimResults = [];

        // Parse from Authentication-Results
        if (authResults) {
            const dkimMatches = authResults.match(/dkim=(\w+)(?:\s+header\.i=@?([^\s]+))?(?:\s+header\.s=([^\s]+))?(?:\s+header\.b=([^\s;]+))?/gi);
            this.log('DKIM regex matches from Authentication-Results', {
                matches: dkimMatches,
                count: dkimMatches ? dkimMatches.length : 0
            });

            if (dkimMatches) {
                dkimMatches.forEach((match, index) => {
                    const details = match.match(/dkim=(\w+)(?:\s+header\.i=@?([^\s]+))?(?:\s+header\.s=([^\s]+))?(?:\s+header\.b=([^\s;]+))?/i);
                    if (details) {
                        const result = {
                            result: details[1],
                            domain: details[2] || '',
                            selector: details[3] || '',
                            signature: details[4] || '',
                            source: 'Authentication-Results'
                        };
                        this.log(`DKIM result ${index + 1} from Auth-Results`, result);
                        dkimResults.push(result);
                    }
                });
            }
        }

        // Parse DKIM-Signature header
        if (dkimSignature) {
            const domain = (dkimSignature.match(/d=([^;\s]+)/) || [])[1];
            const selector = (dkimSignature.match(/s=([^;\s]+)/) || [])[1];

            this.log('DKIM-Signature extraction', { domain, selector });

            const result = {
                result: 'signed',
                domain: domain || '',
                selector: selector || '',
                signature: dkimSignature,
                source: 'DKIM-Signature'
            };
            this.log('DKIM result from DKIM-Signature', result);
            dkimResults.push(result);
        }

        this.log('Total DKIM results found', { count: dkimResults.length, results: dkimResults });
        return dkimResults.length > 0 ? dkimResults : null;
    },

    /**
     * Parses DMARC (Domain-based Message Authentication) results
     */
    parseDMARC(headers) {
        const authResults = this.getHeader(headers, 'Authentication-Results');

        this.log('Raw DMARC header', {
            authResults: authResults
        });

        if (!authResults) {
            this.log('No Authentication-Results header found for DMARC');
            return null;
        }

        const dmarcMatch = authResults.match(/dmarc=(\w+)(?:\s+\(([^)]+)\))?(?:\s+header\.from=([^\s;]+))?/i);
        this.log('DMARC regex match', { match: dmarcMatch });

        if (!dmarcMatch) {
            this.log('No DMARC data found in Authentication-Results');
            return null;
        }

        const details = dmarcMatch[2] || '';
        const policy = (details.match(/p=(\w+)/) || [])[1];
        const subdomainPolicy = (details.match(/sp=(\w+)/) || [])[1];
        const disposition = (details.match(/dis=(\w+)/) || [])[1];

        this.log('DMARC detail extraction', {
            rawDetails: details,
            policy,
            subdomainPolicy,
            disposition
        });

        const result = {
            result: dmarcMatch[1],
            policy: policy || '',
            subdomainPolicy: subdomainPolicy || '',
            disposition: disposition || '',
            domain: dmarcMatch[3] || '',
            details: details
        };

        this.log('DMARC result', result);
        return result;
    },

    /**
     * Parses ARC (Authenticated Received Chain) headers
     */
    parseARC(headers) {
        const arcSeal = headers['ARC-Seal'] || [];
        const arcResults = headers['ARC-Authentication-Results'] || [];
        const arcMessageSig = headers['ARC-Message-Signature'] || [];

        this.log('Raw ARC headers', {
            arcSealCount: arcSeal.length,
            arcResultsCount: arcResults.length,
            arcMessageSigCount: arcMessageSig.length
        });

        if (arcSeal.length === 0) {
            this.log('No ARC-Seal headers found');
            return null;
        }

        const chains = [];

        arcSeal.forEach((seal, index) => {
            const instance = (seal.match(/i=(\d+)/) || [])[1];
            const cv = (seal.match(/cv=(\w+)/) || [])[1];

            this.log(`ARC chain ${index + 1}`, {
                instance,
                chainValidation: cv,
                seal: seal
            });

            chains.push({
                instance: instance || index + 1,
                chainValidation: cv || 'unknown',
                seal: seal,
                authResults: arcResults[index] || '',
                messageSignature: arcMessageSig[index] || ''
            });
        });

        this.log('Total ARC chains found', { count: chains.length });
        return chains.length > 0 ? chains : null;
    },

    /**
     * Parses all Authentication-Results headers
     */
    parseAuthenticationResults(headers) {
        const authResults = headers['Authentication-Results'] || [];
        return authResults.map(result => {
            return {
                raw: result,
                server: (result.match(/^([^;]+)/) || [])[1] || ''
            };
        });
    },

    /**
     * Parses the email's received path
     */
    parseReceivedPath(headers) {
        const received = headers['Received'] || [];
        return received.map((recv, index) => {
            const from = (recv.match(/from\s+([^\s]+)/) || [])[1];
            const by = (recv.match(/by\s+([^\s]+)/) || [])[1];
            const timestamp = (recv.match(/;\s*(.+)$/) || [])[1];

            return {
                hop: index + 1,
                from: from || '',
                by: by || '',
                timestamp: timestamp || '',
                raw: recv
            };
        });
    },

    /**
     * Helper function to get header value
     */
    getHeader(headers, name) {
        const values = headers[name];
        if (!values || values.length === 0) return null;
        return values.length === 1 ? values[0] : values;
    }
};

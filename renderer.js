/**
 * EmailRenderer - Renders parsed email data using card-based layout
 */
const EmailRenderer = {
    /**
     * Renders the parsed email data into the DOM
     * @param {object} parsedData - Data from EmailParser.parse()
     * @param {HTMLElement} container - Container element to render into
     */
    render(parsedData, container) {
        container.innerHTML = '';

        // Render Email Headers section
        if (parsedData.rawHeaders) {
            this.renderMetadataSection(container, parsedData.rawHeaders);
        }

        // Render SPF section
        if (parsedData.authentication?.spf) {
            this.renderSPFSection(container, parsedData.authentication.spf);
        }

        // Render DKIM section
        if (parsedData.authentication?.dkim) {
            this.renderDKIMSection(container, parsedData.authentication.dkim);
        }

        // Render DMARC section
        if (parsedData.authentication?.dmarc) {
            this.renderDMARCSection(container, parsedData.authentication.dmarc);
        }

        // Render ARC section
        if (parsedData.authentication?.arc) {
            this.renderARCSection(container, parsedData.authentication.arc);
        }

        // Render Received Path / Hops section
        if (parsedData.receivedPath && parsedData.receivedPath.length > 0) {
            this.renderReceivedPathSection(container, parsedData.receivedPath);
        }

        // Render Authentication Results Headers section
        if (parsedData.authenticationResults && parsedData.authenticationResults.length > 0) {
            this.renderAuthResultsSection(container, parsedData.authenticationResults);
        }

        // Render Raw Email Headers section
        if (parsedData.rawHeaderSection) {
            this.renderRawEmailSection(container, parsedData.rawHeaderSection);
        }
    },

    /**
     * Renders debug log
     * @param {array} debugLog - Array of debug log entries
     * @param {HTMLElement} container - Container element to render into
     */
    renderDebugLog(debugLog, container) {
        container.innerHTML = '';

        if (!debugLog || debugLog.length === 0) {
            container.innerHTML = '<p>No debug information available</p>';
            return;
        }

        debugLog.forEach((entry, index) => {
            const logEntry = document.createElement('div');
            logEntry.className = 'debug-entry';

            // Entry header
            const entryHeader = document.createElement('div');
            entryHeader.className = 'debug-entry-header';

            const entryNum = document.createElement('span');
            entryNum.className = 'debug-entry-num';
            entryNum.textContent = `#${index + 1}`;

            const entryMsg = document.createElement('span');
            entryMsg.className = 'debug-entry-message';
            entryMsg.textContent = entry.message;

            const entryTime = document.createElement('span');
            entryTime.className = 'debug-entry-time';
            entryTime.textContent = new Date(entry.timestamp).toLocaleTimeString();

            entryHeader.appendChild(entryNum);
            entryHeader.appendChild(entryMsg);
            entryHeader.appendChild(entryTime);
            logEntry.appendChild(entryHeader);

            // Entry data (if exists)
            if (entry.data !== null && entry.data !== undefined) {
                const entryData = document.createElement('pre');
                entryData.className = 'debug-entry-data';
                entryData.textContent = JSON.stringify(entry.data, null, 2);
                logEntry.appendChild(entryData);
            }

            container.appendChild(logEntry);
        });
    },

    /**
     * Creates a section with header
     */
    createSection(title) {
        const section = document.createElement('div');
        section.className = 'analysis-section';

        const header = document.createElement('div');
        header.className = 'section-header';
        header.textContent = title;
        section.appendChild(header);

        const content = document.createElement('div');
        content.className = 'section-content';
        section.appendChild(content);

        return { section, content };
    },

    /**
     * Creates a card element
     */
    createCard(title = null) {
        const card = document.createElement('div');
        card.className = 'info-card';

        if (title) {
            const cardTitle = document.createElement('div');
            cardTitle.className = 'card-title';
            cardTitle.textContent = title;
            card.appendChild(cardTitle);
        }

        const cardContent = document.createElement('div');
        cardContent.className = 'card-content';
        card.appendChild(cardContent);

        return { card, content: cardContent };
    },

    /**
     * Adds a row to card content
     */
    addCardRow(cardContent, label, value, isMonospace = false) {
        if (value === null || value === undefined || value === '') return;

        const row = document.createElement('div');
        row.className = 'card-row';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'card-label';
        labelSpan.textContent = label + ':';

        const valueSpan = document.createElement('span');
        valueSpan.className = 'card-value';
        if (isMonospace) {
            valueSpan.classList.add('monospace');
        }
        valueSpan.textContent = value;

        row.appendChild(labelSpan);
        row.appendChild(valueSpan);
        cardContent.appendChild(row);
    },

    /**
     * Adds a status badge row to card content
     */
    addStatusRow(cardContent, label, status) {
        if (status === null || status === undefined || status === '') return;

        const row = document.createElement('div');
        row.className = 'card-row';

        const labelSpan = document.createElement('span');
        labelSpan.className = 'card-label';
        labelSpan.textContent = label + ':';

        const badge = document.createElement('span');
        badge.className = `status-badge ${this.getStatusClass(status)}`;
        badge.textContent = status.toUpperCase();

        row.appendChild(labelSpan);
        row.appendChild(badge);
        cardContent.appendChild(row);
    },

    /**
     * Renders Email Headers section with all extracted headers
     */
    renderMetadataSection(container, rawHeaders) {
        const section = document.createElement('div');
        section.className = 'analysis-section';

        const header = document.createElement('div');
        header.className = 'section-header';
        header.textContent = 'Email Headers';
        section.appendChild(header);

        const content = document.createElement('div');
        // Don't use grid for headers, stack them vertically
        content.style.display = 'block';

        // Display all headers from rawHeaders
        if (rawHeaders) {
            for (let [headerName, headerValues] of Object.entries(rawHeaders)) {
                // headerValues is an array, display each occurrence
                headerValues.forEach((headerValue, index) => {
                    const headerCard = document.createElement('div');
                    headerCard.className = 'header-card';

                    const nameSpan = document.createElement('div');
                    nameSpan.className = 'header-name';
                    nameSpan.textContent = headerValues.length > 1 ? `${headerName} #${index + 1}` : headerName;

                    const valueSpan = document.createElement('div');
                    valueSpan.className = 'header-value';
                    valueSpan.textContent = headerValue;

                    headerCard.appendChild(nameSpan);
                    headerCard.appendChild(valueSpan);
                    content.appendChild(headerCard);
                });
            }
        }

        section.appendChild(content);
        container.appendChild(section);
    },

    /**
     * Renders SPF section
     */
    renderSPFSection(container, spfData) {
        const { section, content } = this.createSection('SPF (Sender Policy Framework)');

        spfData.forEach((spf, index) => {
            const title = spfData.length > 1 ? `SPF Check ${index + 1}` : null;
            const { card, content: cardContent } = this.createCard(title);

            this.addStatusRow(cardContent, 'Result', spf.result);
            this.addCardRow(cardContent, 'Source', spf.source);
            this.addCardRow(cardContent, 'Details', spf.details);

            content.appendChild(card);
        });

        container.appendChild(section);
    },

    /**
     * Renders DKIM section
     */
    renderDKIMSection(container, dkimData) {
        const { section, content } = this.createSection('DKIM (DomainKeys Identified Mail)');

        dkimData.forEach((dkim, index) => {
            const title = dkimData.length > 1 ? `DKIM Signature ${index + 1}` : null;
            const { card, content: cardContent } = this.createCard(title);

            this.addStatusRow(cardContent, 'Result', dkim.result);
            this.addCardRow(cardContent, 'Domain', dkim.domain);
            this.addCardRow(cardContent, 'Selector', dkim.selector);
            this.addCardRow(cardContent, 'Source', dkim.source);
            this.addCardRow(cardContent, 'Signature', dkim.signature, true);

            content.appendChild(card);
        });

        container.appendChild(section);
    },

    /**
     * Renders DMARC section
     */
    renderDMARCSection(container, dmarcData) {
        const { section, content } = this.createSection('DMARC (Domain-based Message Authentication)');

        const { card, content: cardContent } = this.createCard();

        this.addStatusRow(cardContent, 'Result', dmarcData.result);
        this.addCardRow(cardContent, 'Policy', dmarcData.policy);
        this.addCardRow(cardContent, 'Subdomain Policy', dmarcData.subdomainPolicy);
        this.addCardRow(cardContent, 'Disposition', dmarcData.disposition);
        this.addCardRow(cardContent, 'Domain', dmarcData.domain);
        this.addCardRow(cardContent, 'Details', dmarcData.details);

        content.appendChild(card);
        container.appendChild(section);
    },

    /**
     * Renders ARC section
     */
    renderARCSection(container, arcData) {
        const { section, content } = this.createSection('ARC (Authenticated Received Chain)');

        arcData.forEach((arc) => {
            const { card, content: cardContent } = this.createCard(`Chain ${arc.instance}`);

            this.addStatusRow(cardContent, 'Chain Validation', arc.chainValidation);
            this.addCardRow(cardContent, 'Seal', arc.seal, true);
            this.addCardRow(cardContent, 'Auth Results', arc.authResults, true);
            this.addCardRow(cardContent, 'Message Signature', arc.messageSignature, true);

            content.appendChild(card);
        });

        container.appendChild(section);
    },

    /**
     * Renders Received Path / Hops section
     */
    renderReceivedPathSection(container, receivedPath) {
        const { section, content } = this.createSection('Received Path (Email Hops)');

        receivedPath.forEach((hop) => {
            const { card, content: cardContent } = this.createCard(`Hop ${hop.hop}`);

            this.addCardRow(cardContent, 'From', hop.from);
            this.addCardRow(cardContent, 'By', hop.by);
            this.addCardRow(cardContent, 'Timestamp', hop.timestamp);
            this.addCardRow(cardContent, 'Raw', hop.raw, true);

            content.appendChild(card);
        });

        container.appendChild(section);
    },

    /**
     * Renders Authentication Results Headers section
     */
    renderAuthResultsSection(container, authResults) {
        const { section, content } = this.createSection('Authentication-Results Headers');

        authResults.forEach((result, index) => {
            const { card, content: cardContent } = this.createCard(`Header ${index + 1}`);

            this.addCardRow(cardContent, 'Server', result.server);
            this.addCardRow(cardContent, 'Raw', result.raw, true);

            content.appendChild(card);
        });

        container.appendChild(section);
    },

    /**
     * Renders Raw Email Headers section
     */
    renderRawEmailSection(container, rawHeaderSection) {
        const { section, content } = this.createSection('Raw Email Headers');

        const pre = document.createElement('pre');
        pre.className = 'raw-email-content';
        pre.textContent = rawHeaderSection;

        content.appendChild(pre);
        container.appendChild(section);
    },

    /**
     * Gets CSS class based on authentication result
     */
    getStatusClass(value) {
        const val = value.toLowerCase();
        if (val === 'pass' || val === 'signed') return 'pass';
        if (val === 'fail' || val === 'none') return 'fail';
        return 'neutral';
    }
};

/**
 * Parses raw email source for authentication headers (SPF, DKIM, DMARC).
 * @param {string} rawEmail - The full raw string of the email.
 * @returns {Object} Parsed authentication data.
 */
function extractEmailAuthDetails(rawEmail) {
  const authData = {
    spf: { raw: null, result: null, params: {} },
    dkim: [], // Can have multiple signatures
    dmarc: { raw: null, result: null, params: {} },
    allAuthHeaders: []
  };

  // 1. Split headers from body (we only care about the top section)
  const headerSection = rawEmail.split(/\r?\n\r?\n/)[0];

  // 2. Helper to parse semicolon-separated KV pairs (e.g., k1=v1; k2=v2)
  const parseKVPairs = (str) => {
    const pairs = {};
    str.split(';').forEach(part => {
      const [key, ...val] = part.trim().split('=');
      if (key) pairs[key.trim()] = val.join('=').trim();
    });
    return pairs;
  };

  // 3. Extract Headers using Regex
  // Regex handles multi-line headers (folding white space)
  const headerRegex = /^([a-zA-Z0-9-]+):\s*([\s\S]*?)(?=\r?\n[^\s]|$)/gm;
  let match;

  while ((match = headerRegex.exec(headerSection)) !== null) {
    const name = match[1].toLowerCase();
    const value = match[2].replace(/\r?\n\s+/g, ' ').trim(); // Unfold lines

    // Store in general list
    if (['received-spf', 'dkim-signature', 'authentication-results'].includes(name)) {
      authData.allAuthHeaders.push({ header: match[1], value });
    }

    // Parse SPF
    if (name === 'received-spf') {
      authData.spf.raw = value;
      authData.spf.result = value.split(' ')[0]; // e.g., "pass" or "fail"
      authData.spf.params = parseKVPairs(value);
    }

    // Parse DKIM (supports multiple signatures)
    if (name === 'dkim-signature') {
      authData.dkim.push({
        raw: value,
        params: parseKVPairs(value)
      });
    }

    // Parse DMARC (found within Authentication-Results)
    if (name === 'authentication-results') {
      if (value.includes('dmarc=')) {
        authData.dmarc.raw = value;
        const dmarcMatch = value.match(/dmarc=([a-z]+)/i);
        authData.dmarc.result = dmarcMatch ? dmarcMatch[1] : null;
        authData.dmarc.params = parseKVPairs(value);
      }
    }
  }

  return authData;
}
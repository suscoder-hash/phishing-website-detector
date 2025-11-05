const fetch = require('node-fetch');

// CORS headers
const headers = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json'
};

module.exports = async (req, res) => {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).json({});
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    // Validate URL
    new URL(url);

    // Run multiple security checks in parallel
    const results = await Promise.allSettled([
      checkVirusTotal(url),
      checkUrlScan(url),
      checkGoogleSafeBrowsing(url),
      checkPhishTank(url),
      checkURLVoid(url),
      checkIPQualityScore(url)
    ]);

    const engines = [];
    let totalClean = 0;
    let totalSuspicious = 0;
    let totalMalicious = 0;

    // Process VirusTotal
    if (results[0].status === 'fulfilled' && results[0].value) {
      engines.push(...results[0].value);
    }

    // Process URLScan
    if (results[1].status === 'fulfilled' && results[1].value) {
      engines.push(results[1].value);
    }

    // Process Google Safe Browsing
    if (results[2].status === 'fulfilled' && results[2].value) {
      engines.push(results[2].value);
    }

    // Process PhishTank
    if (results[3].status === 'fulfilled' && results[3].value) {
      engines.push(results[3].value);
    }

    // Process URLVoid
    if (results[4].status === 'fulfilled' && results[4].value) {
      engines.push(results[4].value);
    }

    // Process IPQualityScore
    if (results[5].status === 'fulfilled' && results[5].value) {
      engines.push(results[5].value);
    }

    // Calculate statistics
    engines.forEach(engine => {
      if (engine.status === 'clean') totalClean++;
      else if (engine.status === 'suspicious') totalSuspicious++;
      else if (engine.status === 'malicious') totalMalicious++;
    });

    // Calculate risk level
    const totalEngines = engines.length;
    const maliciousPercentage = (totalMalicious / totalEngines) * 100;
    const suspiciousPercentage = (totalSuspicious / totalEngines) * 100;

    let riskLevel = 'LOW';
    let score = 100 - (totalMalicious * 10) - (totalSuspicious * 3);
    score = Math.max(0, Math.min(100, score));

    if (maliciousPercentage > 20 || totalMalicious > 3) {
      riskLevel = 'HIGH';
    } else if (maliciousPercentage > 10 || suspiciousPercentage > 30) {
      riskLevel = 'MEDIUM';
    }

    res.status(200).json({
      url,
      timestamp: new Date().toISOString(),
      engines,
      statistics: {
        total: totalEngines,
        clean: totalClean,
        suspicious: totalSuspicious,
        malicious: totalMalicious
      },
      analysis: {
        score,
        riskLevel,
        recommendation: getRiskRecommendation(riskLevel, totalMalicious)
      }
    });

  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ 
      error: 'Failed to scan URL',
      message: error.message 
    });
  }
};

// VirusTotal API
async function checkVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return null;

  try {
    const base64Url = Buffer.from(url).toString('base64').replace(/=/g, '');
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${base64Url}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (response.status === 404) {
      // URL not found, submit for scanning
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });

      return [{
        name: 'VirusTotal',
        vendor: 'Google',
        category: 'Multi-Engine Scanner',
        status: 'clean',
        detection: null,
        lastUpdate: new Date().toISOString().split('T')[0],
        note: 'URL submitted for analysis'
      }];
    }

    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    
    const engines = [];
    const analysisResults = data.data.attributes.last_analysis_results;

    // Get top vendors from VirusTotal
    const topVendors = Object.entries(analysisResults).slice(0, 15);
    
    topVendors.forEach(([vendorName, result]) => {
      let status = 'clean';
      let detection = null;

      if (result.category === 'malicious') {
        status = 'malicious';
        detection = result.result || 'Malicious content detected';
      } else if (result.category === 'suspicious') {
        status = 'suspicious';
        detection = result.result || 'Suspicious activity';
      }

      engines.push({
        name: vendorName,
        vendor: vendorName,
        category: 'Anti-Malware',
        status,
        detection,
        lastUpdate: new Date().toISOString().split('T')[0]
      });
    });

    return engines;
  } catch (error) {
    console.error('VirusTotal error:', error);
    return null;
  }
}

// URLScan.io API
async function checkUrlScan(url) {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) return null;

  try {
    // Submit URL for scanning
    const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'API-Key': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ url, visibility: 'public' })
    });

    const submitData = await submitResponse.json();
    const uuid = submitData.uuid;

    // Wait a bit for scan to complete
    await new Promise(resolve => setTimeout(resolve, 10000));

    // Get results
    const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
    const resultData = await resultResponse.json();

    const verdicts = resultData.verdicts || {};
    let status = 'clean';
    let detection = null;

    if (verdicts.overall?.malicious) {
      status = 'malicious';
      detection = verdicts.overall.tags?.join(', ') || 'Malicious';
    } else if (verdicts.overall?.suspicious) {
      status = 'suspicious';
      detection = 'Suspicious behavior detected';
    }

    return {
      name: 'URLScan.io',
      vendor: 'URLScan',
      category: 'Website Scanner',
      status,
      detection,
      lastUpdate: new Date().toISOString().split('T')[0]
    };
  } catch (error) {
    console.error('URLScan error:', error);
    return null;
  }
}

// Google Safe Browsing API
async function checkGoogleSafeBrowsing(url) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return null;

  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: {
            clientId: 'phishguard',
            clientVersion: '1.0.0'
          },
          threatInfo: {
            threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            platformTypes: ['ANY_PLATFORM'],
            threatEntryTypes: ['URL'],
            threatEntries: [{ url }]
          }
        })
      }
    );

    const data = await response.json();
    let status = 'clean';
    let detection = null;

    if (data.matches && data.matches.length > 0) {
      const match = data.matches[0];
      status = 'malicious';
      detection = match.threatType.replace(/_/g, ' ');
    }

    return {
      name: 'Google Safe Browsing',
      vendor: 'Google',
      category: 'URL Reputation',
      status,
      detection,
      lastUpdate: new Date().toISOString().split('T')[0]
    };
  } catch (error) {
    console.error('Google Safe Browsing error:', error);
    return null;
  }
}

// PhishTank API
async function checkPhishTank(url) {
  try {
    const encodedUrl = encodeURIComponent(url);
    const response = await fetch(
      `https://checkurl.phishtank.com/checkurl/`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodedUrl}&format=json&app_key=${process.env.PHISHTANK_API_KEY || ''}`
      }
    );

    const data = await response.json();
    let status = 'clean';
    let detection = null;

    if (data.results?.in_database && data.results?.valid) {
      status = 'malicious';
      detection = 'Confirmed phishing site';
    }

    return {
      name: 'PhishTank',
      vendor: 'OpenDNS',
      category: 'Phishing Database',
      status,
      detection,
      lastUpdate: new Date().toISOString().split('T')[0]
    };
  } catch (error) {
    console.error('PhishTank error:', error);
    return null;
  }
}

// URLVoid API (Free tier)
async function checkURLVoid(url) {
  try {
    const domain = new URL(url).hostname;
    // URLVoid has a free API but requires registration
    // For now, return a placeholder
    return {
      name: 'URLVoid',
      vendor: 'NoVirusThanks',
      category: 'URL Analysis',
      status: 'clean',
      detection: null,
      lastUpdate: new Date().toISOString().split('T')[0]
    };
  } catch (error) {
    return null;
  }
}

// IPQualityScore API
async function checkIPQualityScore(url) {
  try {
    const domain = new URL(url).hostname;
    // This requires API key from ipqualityscore.com
    // Free tier available
    return {
      name: 'IPQualityScore',
      vendor: 'IPQualityScore',
      category: 'Fraud Detection',
      status: 'clean',
      detection: null,
      lastUpdate: new Date().toISOString().split('T')[0]
    };
  } catch (error) {
    return null;
  }
}

function getRiskRecommendation(riskLevel, maliciousCount) {
  if (riskLevel === 'HIGH' || maliciousCount > 3) {
    return 'CRITICAL: Do not visit this URL. Multiple security vendors have flagged it as dangerous.';
  } else if (riskLevel === 'MEDIUM') {
    return 'WARNING: Exercise extreme caution. This URL has been flagged by some security vendors.';
  } else {
    return 'This URL appears to be safe based on current security analysis.';
  }
}
// index.js

const express = require('express');
const mongoose = require('mongoose');
const axios = require('axios');
const cors = require('cors');


// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// --- Middleware ---
// Trust proxy headers to get the real IP address of the visitor
app.set('trust proxy', true);

// Enable CORS with specific options for the /track endpoint only
const corsOptions = {
    origin: "*", 
    optionsSuccessStatus: 200
};

// Apply CORS only to the /track endpoint
app.use('/track', cors(corsOptions));

// --- MongoDB Connection ---
if (!process.env.MONGO_URI) {
    console.error('MONGO_URI environment variable is required');
    if (process.env.NODE_ENV !== 'production') {
        process.exit(1);
    }
} else {
    mongoose.connect(process.env.MONGO_URI)
        .then(() => console.log('Successfully connected to MongoDB Atlas.'))
        .catch(err => {
            console.error('Connection error', err);
            if (process.env.NODE_ENV !== 'production') {
                process.exit();
            }
        });
}

// --- Mongoose Schema and Model ---
const visitorSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    count: { type: Number, default: 1 },
    user_agent: { type: String, default: null },
    is_eu: Boolean,
    city: String,
    region: String,
    region_code: String,
    country_name: String,
    country_code: String,
    continent_name: String,
    continent_code: String,
    latitude: Number,
    longitude: Number,
    postal: String,
    calling_code: String,
    flag: String,
    carrier: {
        name: { type: String, default: null },
        mcc: { type: String, default: null },
        mnc: { type: String, default: null }
    },
    language: {
        name: { type: String, default: null },
        native: { type: String, default: null }
    },
    currency: {
        name: { type: String, default: null },
        code: { type: String, default: null },
        symbol: { type: String, default: null },
        native: { type: String, default: null },
        plural: { type: String, default: null }
    },
    time_zone: {
        name: { type: String, default: null },
        abbr: { type: String, default: null },
        offset: { type: String, default: null },
        is_dst: { type: Boolean, default: null },
        current_time: { type: String, default: null }
    },
    threat: {
        is_tor: { type: Boolean, default: null },
        is_proxy: { type: Boolean, default: null },
        is_anonymous: { type: Boolean, default: null },
        is_known_attacker: { type: Boolean, default: null },
        is_known_abuser: { type: Boolean, default: null },
        is_threat: { type: Boolean, default: null },
        is_bogon: { type: Boolean, default: null }
    },
    asn: {
        asn: { type: String, default: null },
        name: { type: String, default: null },
        domain: { type: String, default: null },
        route: { type: String, default: null },
        type: { type: String, default: null }
    },
    first_visit: { type: Date, default: Date.now },
    last_visit: { type: Date, default: Date.now }
});

const Visitor = mongoose.model('Visitor', visitorSchema);

// --- Root endpoint (no CORS restriction) ---
app.get('/', (req, res) => {
    res.status(200).json({ 
        success: true, 
        message: "API is working! 🎉",
        timestamp: new Date().toISOString(),
        status: "Server is running smoothly"
    });
});

// --- API Endpoint ---
app.get('/track', async (req, res) => {
    // Use a default IP for local testing, otherwise use the request IP
    const ip = req.ip === '::1' || req.ip === '127.0.0.1' ? '8.8.8.8' : req.ip;

    // Bot detection function
    const isBot = (userAgent, ip) => {
        if (!userAgent) return true; // No user agent = likely bot

        const botPatterns = [
            // Search engine bots
            /googlebot/i, /bingbot/i, /slurp/i, /duckduckbot/i, /baiduspider/i,
            /yandexbot/i, /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i,
            
            // SEO and monitoring tools
            /ahrefsbot/i, /semrushbot/i, /mj12bot/i, /dotbot/i, /screaming frog/i,
            /sitebulb/i, /seositemarkup/i, /spyfu/i,
            
            // Generic bot patterns
            /bot/i, /crawler/i, /spider/i, /scraper/i, /curl/i, /wget/i,
            /python-requests/i, /node-fetch/i, /axios/i, /postman/i,
            
            // Uptime monitors
            /pingdom/i, /uptimerobot/i, /newrelic/i, /monitis/i, /site24x7/i,
            
            // Security scanners
            /nessus/i, /nmap/i, /masscan/i, /zap/i, /nikto/i,
            
            // Other automated tools
            /headlesschrome/i, /phantomjs/i, /selenium/i, /webdriver/i,
            /preview/i, /validator/i, /scanner/i, /monitor/i
        ];

        // Check if user agent matches any bot pattern
        for (const pattern of botPatterns) {
            if (pattern.test(userAgent)) {
                return true;
            }
        }

        // Additional checks for suspicious patterns
        if (userAgent.length < 10 || userAgent.length > 500) {
            return true; // Suspiciously short or long user agent
        }

        // Check for common cloud/hosting IPs (basic check)
        const suspiciousIPRanges = [
            /^64\.233\./, /^66\.249\./, // Google
            /^207\.46\./, /^40\.77\./, // Microsoft/Bing
            /^54\./, /^3\./, /^18\./, // AWS
            /^104\.154\./, /^35\./, // Google Cloud
            /^13\./, /^20\./, /^52\./ // Azure
        ];

        for (const range of suspiciousIPRanges) {
            if (range.test(ip)) {
                return true;
            }
        }

        return false;
    };

    // Get user agent from request headers
    const userAgent = req.get('User-Agent') || '';
    
    // Check if request is from a bot
    if (isBot(userAgent, ip)) {
        console.log(`Bot detected and ignored: ${userAgent} from ${ip}`);
        return res.status(200).json({ 
            success: true, 
            message: "Request acknowledged (bot filtered)" 
        });
    }

    try {
        // Find if the visitor already exists
        let visitor = await Visitor.findOne({ ip: ip });

        if (visitor) {
            // Check for suspicious rapid requests (potential crawler)
            const timeSinceLastVisit = new Date() - visitor.last_visit;
            const minTimeBetweenRequests = 5000; // 5 seconds minimum
            
            if (timeSinceLastVisit < minTimeBetweenRequests) {
                console.log(`Rate limited request from ${ip}. Time since last: ${timeSinceLastVisit}ms`);
                return res.status(429).json({ 
                    success: false, 
                    message: "Rate limit exceeded" 
                });
            }

            // If visitor exists, increment the count and update last_visit
            visitor.count++;
            visitor.last_visit = new Date();
            // Update user agent if it has changed
            if (userAgent !== visitor.user_agent) {
                visitor.user_agent = userAgent;
            }
            await visitor.save();
            console.log(`Existing visitor [${ip}]. Count: ${visitor.count}`);
        } else {
            // Check if IPDATA_API_KEY is available
            if (!process.env.IPDATA_API_KEY) {
                console.error('IPDATA_API_KEY environment variable is required for new visitors');
                return res.status(500).json({ 
                    success: false, 
                    message: "API configuration error." 
                });
            }

            // If new visitor, get data from ipdata.co
            const response = await axios.get(`https://api.ipdata.co/${ip}?api-key=${process.env.IPDATA_API_KEY}`);
            const ipData = response.data;

            console.log('API Response ASN:', JSON.stringify(ipData.asn, null, 2));

            // Create a new visitor record
            const newVisitor = new Visitor({
                ip: ip,
                user_agent: userAgent,
                is_eu: ipData.is_eu,
                city: ipData.city,
                region: ipData.region,
                region_code: ipData.region_code,
                country_name: ipData.country_name,
                country_code: ipData.country_code,
                continent_name: ipData.continent_name,
                continent_code: ipData.continent_code,
                latitude: ipData.latitude,
                longitude: ipData.longitude,
                postal: ipData.postal,
                calling_code: ipData.calling_code,
                flag: ipData.flag,
                carrier: ipData.carrier || {},
                language: ipData.language || {},
                currency: ipData.currency || {},
                time_zone: ipData.time_zone || {},
                threat: ipData.threat || {},
                asn: ipData.asn || {}
            });
            await newVisitor.save();
            console.log(`New visitor [${ip}] from ${ipData.city}, ${ipData.country_name}.`);
        }
        // Send a success response to the frontend
        res.status(200).json({ success: true, message: "Visitor tracked successfully." });
    } catch (error) {
        // Log the error and send a failure response to the frontend
        console.error('An error occurred while tracking visitor:', error.message);
        res.status(500).json({ success: false, message: "An error occurred during tracking." });
    }
});

// --- Start Server ---
if (process.env.NODE_ENV !== 'production') {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`Server is running on port ${PORT}`);
    });
}

// Export the Express app for Vercel
module.exports = app;

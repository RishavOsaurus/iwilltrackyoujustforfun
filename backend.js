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

// Enable CORS with specific options
// Make sure FRONTEND_URL in your .env file is the exact URL where the HTML file is hosted.
const corsOptions = {
    origin: "*", 
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('Successfully connected to MongoDB Atlas.'))
    .catch(err => {
        console.error('Connection error', err);
        process.exit();
    });

// --- Mongoose Schema and Model ---
const visitorSchema = new mongoose.Schema({
    ip: { type: String, required: true, unique: true },
    count: { type: Number, default: 1 },
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
        name: String,
        mcc: String,
        mnc: String
    },
    language: {
        name: String,
        native: String
    },
    currency: {
        name: String,
        code: String,
        symbol: String,
        native: String,
        plural: String
    },
    time_zone: {
        name: String,
        abbr: String,
        offset: String,
        is_dst: Boolean,
        current_time: String
    },
    threat: {
        is_tor: Boolean,
        is_proxy: Boolean,
        is_anonymous: Boolean,
        is_known_attacker: Boolean,
        is_known_abuser: Boolean,
        is_threat: Boolean,
        is_bogon: Boolean
    },
    asn: {
        asn: String,
        name: String,
        domain: String,
        route: String,
        type: String
    },
    first_visit: { type: Date, default: Date.now },
    last_visit: { type: Date, default: Date.now }
});

const Visitor = mongoose.model('Visitor', visitorSchema);

// --- API Endpoint ---
app.get('/track', async (req, res) => {
    // Use a default IP for local testing, otherwise use the request IP
    const ip = req.ip === '::1' || req.ip === '127.0.0.1' ? '8.8.8.8' : req.ip;

    try {
        // Find if the visitor already exists
        let visitor = await Visitor.findOne({ ip: ip });

        if (visitor) {
            // If visitor exists, increment the count and update last_visit
            visitor.count++;
            visitor.last_visit = new Date();
            await visitor.save();
            console.log(`Existing visitor [${ip}]. Count: ${visitor.count}`);
        } else {
            // If new visitor, get data from ipdata.co
            const response = await axios.get(`https://api.ipdata.co/${ip}?api-key=${process.env.IPDATA_API_KEY}`);
            const ipData = response.data;

            // Create a new visitor record
            const newVisitor = new Visitor({
                ip: ip,
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
                carrier: ipData.carrier,
                language: ipData.language,
                currency: ipData.currency,
                time_zone: ipData.time_zone,
                threat: ipData.threat,
                asn: ipData.asn
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
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

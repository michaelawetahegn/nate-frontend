const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const WebSocket = require('ws');
const cors = require('cors');
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Models
const User = mongoose.model('User', new mongoose.Schema({
    username: String,
    password: String,
    role: String, // 'admin' or 'driver'
}));

const Trip = mongoose.model('Trip', new mongoose.Schema({
    clientName: String,
    pickupLocation: String,
    dropoffLocation: String,
    pickupTime: String,
    appointmentTime: String,
    directions: String,
    driver: String, // Driver assigned
}));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// WebSocket Server
const wss = new WebSocket.Server({ noServer: true });
let connectedClients = [];

// Broadcast updates to all WebSocket clients
const broadcast = (data) => {
    connectedClients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify(data));
        }
    });
};

// Authentication middleware
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// Routes
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET);
    res.json({ token, role: user.role });
});

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword, role });
    await user.save();
    res.json({ message: 'User registered successfully' });
});

app.post('/trips', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const trips = req.body.trips;
    const savedTrips = await Trip.insertMany(trips);
    broadcast(savedTrips);
    res.json(savedTrips);
});

app.get('/trips', authenticate, async (req, res) => {
    const query = req.user.role === 'driver' ? { driver: req.user.id } : {};
    const trips = await Trip.find(query);
    res.json(trips);
});

app.patch('/trips/:id', authenticate, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { id } = req.params;
    const { driver } = req.body;
    const updatedTrip = await Trip.findByIdAndUpdate(id, { driver }, { new: true });
    broadcast(updatedTrip);
    res.json(updatedTrip);
});

// WebSocket integration
app.server = app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
app.server.on('upgrade', (req, socket, head) => {
    wss.handleUpgrade(req, socket, head, (ws) => {
        connectedClients.push(ws);
        ws.on('close', () => {
            connectedClients = connectedClients.filter((client) => client !== ws);
        });
    });
});


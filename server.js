const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose'); 
const path = require('path'); 
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = 3000;
//mongoose
const MONGO_URI = "mongodb://localhost:27017/online_voting_db"; 

mongoose.connect(MONGO_URI)
    .then(() => console.log('MongoDB Connected Successfully.'))
    .catch(err => console.error('MongoDB Connection Error:', err));

// --- Models ---

// Candidate Schema
const CandidateSchema = new mongoose.Schema({
    
    name: { type: String, required: true, trim: true },
    party: { type: String, required: true, trim: true },
    voteCount: { type: Number, default: 0 }
});

const CandidateModel = mongoose.model('Candidate', CandidateSchema);

//user schema
const UserSchema = new mongoose.Schema({
    aadhar: { type: String, required: true, unique: true, index: true, minlength: 12, maxlength: 12 },
    passwordHash: { type: String, required: true },
    name: { type: String, trim: true },
    email: { type: String, trim: true, lowercase: true },
    phone: { type: String, trim: true },
    hasVoted: { type: Boolean, default: false }
});

const UserModel = mongoose.model('User', UserSchema);


const ADMIN_AADHAR = "123456789111";
let ADMIN_PASSWORD_HASH = ""; 


const initializeAdmin = async () => {
    
    ADMIN_PASSWORD_HASH = await bcrypt.hash('meet@123', 10);//10 used for salt round more secure
};
initializeAdmin();


// --- Express Middleware Setup cookieparser helmet morgan ---

app.use(bodyParser.json());//used to read  req.body  parsed data/app.use(express.json());(alternative)


app.use(express.static(path.join(__dirname, 'public'))); //Serve static files from the 'public' directory


app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'voting_app.html'));//home page //Serve the main HTML file at the root path
});


// --- AUTHENTICATION MIDDLEWARE ---

// Middleware to check for a valid logged-in user
const authenticateUser = async (req, res, next) => {
    const aadhar = req.headers['x-aadhar-id'];
    if (!aadhar) {
        return res.status(401).json({ message: "Access denied. Aadhar ID required in header." });
    }//empty

    if (aadhar === ADMIN_AADHAR) {
        req.userId = ADMIN_AADHAR;
        req.userType = 'admin';
        return next();
    }//admin check
    
    // Check if the user exists in the database
    const user = await UserModel.findOne({ aadhar });//normal user

    if (!user) {
        return res.status(401).json({ message: "Access denied. Invalid Aadhar ID." });//invalid user
    }
    
    req.userId = aadhar;
    req.userType = 'user';
    next();
};//user details

// Middleware to check specifically for the admin Aadhar ID
const authenticateAdmin = (req, res, next) => {
    const adminAadhar = req.headers['x-aadhar-id']; 
    if (adminAadhar !== ADMIN_AADHAR) {
        return res.status(403).json({ message: "Admin access required." });
    }
    next();
};

// --- 1. USER AUTHENTICATION ROUTES ---

// POST /signup
app.post('/signup', async (req, res) => {
    const { aadhar, password, name, email, phone } = req.body;

    if (!aadhar || !password) {
        return res.status(400).json({ message: "Aadhar card number and password are required." });
    }

    try {
        // Check if user already exists
        const existingUser = await UserModel.findOne({ aadhar });
        if (existingUser) {
            return res.status(409).json({ message: "User with this Aadhar number already exists." });
        }

        const passwordHash = await bcrypt.hash(password, 10);
        
        await UserModel.create({
            name,
            email,
            phone,
            aadhar,
            passwordHash,
            hasVoted: false
        });
        
        console.log(`New user registered: ${aadhar}`);
        res.status(201).json({ message: "Registration successful. Please log in.", success: true });
    } catch (error) {
        console.error('Signup Error:', error);
        res.status(500).json({ message: "Server error during registration." });
    }
});

// POST /login
app.post('/login', async (req, res) => {
    const { aadhar, password, isAdmin } = req.body;

    if (!aadhar || !password) {
        return res.status(400).json({ message: "Aadhar card number and password are required." });
    }

    // Admin Login Check
    if (isAdmin && aadhar === ADMIN_AADHAR) {
        const match = await bcrypt.compare(password, ADMIN_PASSWORD_HASH);
        if (match) {
            return res.json({ message: "Admin Login Successful.", success: true, userType: 'admin', aadhar: ADMIN_AADHAR });
        }
    }

    // User Login Check
    try {
        const user = await UserModel.findOne({ aadhar });
        if (!user) {
            return res.status(401).json({ message: "Invalid Aadhar card number or password." });
        }

        const match = await bcrypt.compare(password, user.passwordHash);
        if (match) {
            return res.json({ message: "Login Successful.", success: true, userType: 'user', aadhar: user.aadhar });
        } else {
            return res.status(401).json({ message: "Invalid Aadhar card number or password." });
        }
    } catch (error) {
        console.error('Login Error:', error);
        res.status(500).json({ message: "Server error during login." });
    }
});

// GET /profile (User Profile)
app.get('/profile', authenticateUser, async (req, res) => {
    // If admin, return placeholder profile
    if (req.userType === 'admin') {
        return res.json({ name: "Admin User", aadhar: ADMIN_AADHAR, hasVoted: false });
    }

    try {
        const user = await UserModel.findOne({ aadhar: req.userId }, 
            { name: 1, aadhar: 1, email: 1, phone: 1, hasVoted: 1, _id: 0 }); // Select specific fields

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }
        res.json(user);
    } catch (error) {
        console.error('Profile Fetch Error:', error);
        res.status(500).json({ message: "Server error fetching profile." });
    }
});

// PUT /profile/password (Change Password - for registered users only)
app.put('/profile/password', authenticateUser, async (req, res) => {
    if (req.userType === 'admin') {
        return res.status(403).json({ message: "Admin password cannot be changed via the user profile route." });
    }
    
    const { currentPassword, newPassword } = req.body;

    try {
        const user = await UserModel.findOne({ aadhar: req.userId });
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        const match = await bcrypt.compare(currentPassword, user.passwordHash);
        if (!match) {
            return res.status(401).json({ message: "Current password is incorrect." });
        }

        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        
        await UserModel.updateOne({ aadhar: req.userId }, { passwordHash: newPasswordHash });

        res.json({ message: "Password updated successfully.", success: true });
    } catch (error) {
        console.error('Password Update Error:', error);
        res.status(500).json({ message: "Server error while updating password." });
    }
});


// --- 2. VOTING ROUTES (User Side) ---

// GET /candidates
app.get('/candidates', authenticateUser, async (req, res) => {
    try {
        const candidates = await CandidateModel.find({}, { name: 1, party: 1, _id: 1 });
        // Map Mongoose _id to 'id' for frontend compatibility
        const candidatesArray = candidates.map(c => ({
            id: c._id.toString(),
            name: c.name,
            party: c.party
        }));
        res.json(candidatesArray);
    } catch (error) {
        console.error('Candidate Fetch Error:', error);
        res.status(500).json({ message: "Server error fetching candidates." });
    }
});

// POST /vote/:candidateId
app.post('/vote/:candidateId', authenticateUser, async (req, res) => {
    if (req.userType === 'admin') {
        return res.status(403).json({ message: "Admin users are not allowed to cast votes." });
    }

    const candidateId = req.params.candidateId;

    try {
        const user = await UserModel.findOne({ aadhar: req.userId });
        if (!user) return res.status(404).json({ message: "User not found." });

        if (user.hasVoted) {
            return res.status(403).json({ message: "You have already cast your vote. One Aadhar number = One Vote." });
        }
        
        // 1. Update Candidate vote count
        const candidateUpdateResult = await CandidateModel.findByIdAndUpdate(
            candidateId, 
            { $inc: { voteCount: 1 } }, 
            { new: true }
        );

        if (!candidateUpdateResult) {
            return res.status(404).json({ message: "Invalid candidate ID." });
        }

        // 2. Update User voted status
        await UserModel.updateOne({ aadhar: req.userId }, { hasVoted: true });

        console.log(`User ${req.userId} voted for ${candidateUpdateResult.name}`);
        res.json({ message: "Vote successfully cast. Your account is now locked from further voting.", success: true });

    } catch (error) {
        console.error('Voting Error:', error);
        // If candidateId is invalid format, Mongoose throws a CastError (400)
        if (error.name === 'CastError') {
             return res.status(400).json({ message: "Invalid candidate ID format." });
        }
        res.status(500).json({ message: "Server error during voting." });
    }
});

// --- 3. VOTE COUNTS / RESULTS ---

// GET /vote/counts
app.get('/vote/counts', authenticateUser, async (req, res) => {
    try {
        const results = await CandidateModel.find({}).sort({ voteCount: -1 });
        
        // Map Mongoose _id to 'id' for frontend compatibility
        const resultsArray = results.map(r => ({
            id: r._id.toString(),
            name: r.name,
            party: r.party,
            voteCount: r.voteCount
        }));

        res.json(resultsArray);
    } catch (error) {
        console.error('Results Fetch Error:', error);
        res.status(500).json({ message: "Server error fetching vote counts." });
    }
});


// --- 4. ADMIN CANDIDATE MANAGEMENT ROUTES ---

// POST /candidates (Admin only)
app.post('/candidates', authenticateAdmin, async (req, res) => {
    const { name, party } = req.body;
    if (!name || !party) {
        return res.status(400).json({ message: "Candidate name and party are required." });
    }
    
    try {
        const newCandidate = await CandidateModel.create({ name, party });
        // Send back the new candidate with the generated MongoDB ID
        res.status(201).json({ 
            message: "Candidate added successfully.", 
            candidate: { 
                id: newCandidate._id.toString(), 
                name: newCandidate.name, 
                party: newCandidate.party
            }, 
            success: true 
        });
    } catch (error) {
        console.error('Add Candidate Error:', error);
        res.status(500).json({ message: "Server error adding candidate." });
    }
});

// PUT /candidates/:candidateId (Admin only)
app.put('/candidates/:candidateId', authenticateAdmin, async (req, res) => {
    const candidateId = req.params.candidateId;
    const { name, party } = req.body;
    
    const updates = {};
    if (name) updates.name = name;
    if (party) updates.party = party;

    try {
        const updatedCandidate = await CandidateModel.findByIdAndUpdate(candidateId, updates, { new: true });

        if (!updatedCandidate) {
            return res.status(404).json({ message: "Candidate not found." });
        }

        res.json({ message: "Candidate updated successfully.", success: true });
    } catch (error) {
        console.error('Update Candidate Error:', error);
         if (error.name === 'CastError') {
             return res.status(400).json({ message: "Invalid candidate ID format." });
        }
        res.status(500).json({ message: "Server error updating candidate." });
    }
});

// DELETE /candidates/:candidateId (Admin only)
app.delete('/candidates/:candidateId', authenticateAdmin, async (req, res) => {
    const candidateId = req.params.candidateId;
    
    try {
        const deletedCandidate = await CandidateModel.findByIdAndDelete(candidateId);

        if (!deletedCandidate) {
            return res.status(404).json({ message: "Candidate not found." });
        }

        res.json({ message: "Candidate deleted successfully.", success: true });
    } catch (error) {
        console.error('Delete Candidate Error:', error);
         if (error.name === 'CastError') {
             return res.status(400).json({ message: "Invalid candidate ID format." });
        }
        res.status(500).json({ message: "Server error deleting candidate." });
    }
});


// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    console.log("Access the frontend at http://localhost:3000/");
    console.log("Admin Aadhar: 123456789111 | Password: meet@123");
});
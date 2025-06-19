const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { OAuth2Client } = require('google-auth-library');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const { sendEmail } = require('./emailConfig');
const app = express();

// Google OAuth configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID, null, {
    // Disable the deprecated package warning
    ignoreDeprecationWarning: true
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));
app.use('/image', express.static(path.join(__dirname, 'image')));
app.use('/uploads', express.static(path.join(__dirname, config.uploadDir)));
app.use(helmet({
    contentSecurityPolicy: false // Disable CSP for development
}));
app.use(express.json({ limit: '10kb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Update the upload directory configuration for Vercel
const uploadsDir = process.env.NODE_ENV === 'production' 
    ? path.join(__dirname, 'public', 'uploads')  // Use public/uploads for persistence
    : path.join(__dirname, 'uploads');

// Ensure upload directory exists
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Also ensure public/uploads exists for static serving
const publicUploadsDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(publicUploadsDir)) {
    fs.mkdirSync(publicUploadsDir, { recursive: true });
}

// Remove duplicate uploads directory if it exists
const duplicateDir = path.join(__dirname, 'public', 'updloads');
if (fs.existsSync(duplicateDir)) {
    fs.rmdirSync(duplicateDir, { recursive: true });
}

// MongoDB Connection with improved error handling
const connectDB = async () => {
    try {
        const options = {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            retryWrites: true,
            w: 'majority'
        };

        await mongoose.connect(config.mongoUri, options);
        console.log('Successfully connected to MongoDB Atlas');
    } catch (err) {
        console.error('MongoDB connection error:', err);
        // In production, we'll retry the connection
        if (process.env.NODE_ENV === 'production') {
            console.log('Retrying connection in 5 seconds...');
            setTimeout(connectDB, 5000);
        } else {
            process.exit(1);
        }
    }
};

// Connect to MongoDB
connectDB();

// Add connection event handlers
mongoose.connection.on('connected', () => {
    console.log('Mongoose connected to MongoDB Atlas');
});

mongoose.connection.on('error', (err) => {
    console.error('Mongoose connection error:', err);
    if (process.env.NODE_ENV === 'production') {
        console.log('Attempting to reconnect...');
        setTimeout(connectDB, 5000);
    }
});

mongoose.connection.on('disconnected', () => {
    console.log('Mongoose disconnected from MongoDB Atlas');
    if (process.env.NODE_ENV === 'production') {
        console.log('Attempting to reconnect...');
        setTimeout(connectDB, 5000);
    }
});

// Handle application termination
process.on('SIGINT', async () => {
    try {
        await mongoose.connection.close();
        console.log('Mongoose connection closed through app termination');
        process.exit(0);
    } catch (err) {
        console.error('Error during MongoDB connection closure:', err);
        process.exit(1);
    }
});

// Configure multer storage
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

// Separate file filters for journals and profile photos
const journalFileFilter = (req, file, cb) => {
    // Accept only PDF and Word documents
    const allowedTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    ];
    
    if (allowedTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF and Word documents are allowed.'), false);
    }
};

const photoFileFilter = (req, file, cb) => {
    // Accept only image files
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only image files are allowed.'), false);
    }
};

// Create separate upload instances for journals and photos
const uploadJournal = multer({
    storage: storage,
    fileFilter: journalFileFilter,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB limit
    }
});

const uploadPhoto = multer({
    storage: storage,
    fileFilter: photoFileFilter,
    limits: {
        fileSize: 2 * 1024 * 1024 // 2MB limit
    }
});

// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    registrationDate: { type: Date, default: Date.now },
    lastLoginAttempt: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    accountLocked: { type: Boolean, default: false },
    lockExpiry: { type: Date },
    lastPasswordChange: { type: Date, default: Date.now },
    passwordHistory: [{ type: String }],
    journalCount: { type: Number, default: 0 },
    profilePhoto: { type: String },
    verificationPin: { type: String },
    pinExpiry: { type: Date },
    resetToken: { type: String },
    resetExpiry: { type: Date },
    isVerified: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);

// Journal Schema
const journalSchema = new mongoose.Schema({
    title: { type: String, required: true },
    category: { type: String, required: true },
    description: { type: String, required: true },
    authors: { type: [String], default: [] },
    editors: { type: [String], default: [] },
    associateEditors: { type: [String], default: [] },
    fileUrl: { type: String, required: true },
    uploadDate: { type: Date, default: Date.now },
    status: { type: String, default: 'pending' },
    views: { type: Number, default: 0 },
    citations: { type: Number, default: 0 },
    downloads: { type: Number, default: 0 }
});

const Journal = mongoose.model('Journal', journalSchema);

// Serve index.html as the default page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/journal-library', (req, res) => {
    res.sendFile(path.join(__dirname, 'journal-library.html'));
});

app.get('/author-profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'author-profile.html'));
});

// Serve static files
app.get('/styles.css', (req, res) => {
    res.sendFile(path.join(__dirname, 'styles.css'));
});

// API Routes
app.post('/api/journals/upload', uploadJournal.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const { title, category, description, authors, editors, associateEditors } = req.body;
        console.log('Received data:', { title, category, description, authors, editors, associateEditors });

        if (!title || !category || !description) {
            // Delete the uploaded file if required fields are missing
            fs.unlinkSync(req.file.path);
            return res.status(400).json({ message: 'Missing required fields' });
        }

        // Process authors, editors, and associate editors
        const processedAuthors = authors ? authors.split(',').map(author => author.trim()).filter(author => author) : [];
        const processedEditors = editors ? editors.split(',').map(editor => editor.trim()).filter(editor => editor) : [];
        const processedAssociateEditors = associateEditors ? associateEditors.split(',').map(editor => editor.trim()).filter(editor => editor) : [];

        console.log('Processed contributors:', {
            authors: processedAuthors,
            editors: processedEditors,
            associateEditors: processedAssociateEditors
        });

        // Create new journal entry
        const journal = new Journal({
            title,
            category,
            description,
            authors: processedAuthors,
            editors: processedEditors,
            associateEditors: processedAssociateEditors,
            fileUrl: `/uploads/${req.file.filename}`,
            uploadDate: new Date(),
            status: 'pending',
            views: 0,
            citations: 0,
            downloads: 0
        });

        const savedJournal = await journal.save();
        console.log('Saved journal:', savedJournal);

        // Update user's journal count if needed
        if (processedAuthors.length > 0) {
            const mainAuthor = processedAuthors[0]; // First author is considered the main author
            await User.findOneAndUpdate(
                { name: mainAuthor },
                { $inc: { journalCount: 1 } },
                { new: true }
            );
        }

        // Send submission confirmation email
        if (processedAuthors.length > 0) {
            const mainAuthor = processedAuthors[0];
            const author = await User.findOne({ name: mainAuthor });
            if (author) {
                await sendEmail(author.email, 'journalSubmission', {
                    name: author.name,
                    journalTitle: title
                });
            }
        }

        res.status(201).json(savedJournal);
    } catch (error) {
        console.error('Error uploading journal:', error);
        // Delete the uploaded file if there's an error
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Error uploading journal: ' + error.message });
    }
});

// Get all journals
app.get('/api/journals', async (req, res) => {
    try {
        // Check database connection
        if (mongoose.connection.readyState !== 1) {
            console.error('Database not connected. Current state:', mongoose.connection.readyState);
            return res.status(503).json({ message: 'Database connection not ready' });
        }

        const journals = await Journal.find()
            .sort({ uploadDate: -1 })
            .lean()
            .exec();

        console.log(`Successfully retrieved ${journals.length} journals`);
        
        // Log first few journals for debugging
        if (journals.length > 0) {
            console.log('Sample journals:', journals.slice(0, 3).map(j => ({
                id: j._id,
                title: j.title,
                authors: j.authors
            })));
        }

        res.json(journals);
    } catch (error) {
        console.error('Error fetching journals:', error);
        res.status(500).json({ 
            message: 'Error fetching journals',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

// Get journal by ID
app.get('/api/journals/:id', async (req, res) => {
    try {
        const journal = await Journal.findById(req.params.id);
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }
        res.json(journal);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching journal' });
    }
});

// Update journal
app.put('/api/journals/:id', async (req, res) => {
    try {
        const { title, category, description, authors, editors, associateEditors } = req.body;
        
        if (!title || !category || !description) {
            return res.status(400).json({ message: 'Missing required fields' });
        }

        const journal = await Journal.findByIdAndUpdate(
            req.params.id,
            {
                title,
                category,
                description,
                authors: authors || [],
                editors: editors || [],
                associateEditors: associateEditors || []
            },
            { new: true }
        );

        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }

        res.json(journal);
    } catch (error) {
        console.error('Error updating journal:', error);
        res.status(500).json({ message: 'Error updating journal' });
    }
});

// Delete journal
app.delete('/api/journals/:id', async (req, res) => {
    try {
        const journal = await Journal.findById(req.params.id);
        
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }

        // Delete the associated file
        const filePath = path.join(__dirname, 'public', journal.fileUrl);
        if (fs.existsSync(filePath)) {
            fs.unlinkSync(filePath);
        }

        // Delete the journal from database
        await Journal.findByIdAndDelete(req.params.id);

        res.json({ message: 'Journal deleted successfully' });
    } catch (error) {
        console.error('Error deleting journal:', error);
        res.status(500).json({ message: 'Error deleting journal' });
    }
});

// Authentication Routes
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const user = new User({
            name,
            email,
            password: hashedPassword,
            registrationDate: new Date()
        });

        await user.save();

        res.status(201).json({ 
            message: 'Registration successful. You can now login.',
            user: {
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ message: 'Error registering user' });
    }
});

// Update login endpoint with simplified validation
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Email not found' });
        }

        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Incorrect password' });
        }

        // Get user's journals count
        const journalCount = await Journal.countDocuments({ authors: user.name });

        res.json({ 
            message: 'Login successful',
            user: {
                name: user.name,
                email: user.email,
                journalCount: journalCount,
                registrationDate: user.registrationDate,
                profilePhoto: user.profilePhoto
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Error logging in' });
    }
});

// Update view count
app.post('/api/journals/:id/view', async (req, res) => {
    try {
        const journal = await Journal.findByIdAndUpdate(
            req.params.id,
            { $inc: { views: 1 } },
            { new: true }
        );
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }
        res.json({ views: journal.views });
    } catch (error) {
        res.status(500).json({ message: 'Error updating view count' });
    }
});

// Update citation count
app.post('/api/journals/:id/cite', async (req, res) => {
    try {
        const journal = await Journal.findByIdAndUpdate(
            req.params.id,
            { $inc: { citations: 1 } },
            { new: true }
        );
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }
        res.json({ citations: journal.citations });
    } catch (error) {
        res.status(500).json({ message: 'Error updating citation count' });
    }
});

// Update download count
app.post('/api/journals/:id/download', async (req, res) => {
    try {
        const journal = await Journal.findByIdAndUpdate(
            req.params.id,
            { $inc: { downloads: 1 } },
            { new: true }
        );
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }
        res.json({ downloads: journal.downloads });
    } catch (error) {
        res.status(500).json({ message: 'Error updating download count' });
    }
});

// Get journal file
app.get('/api/journals/:id/file', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: 'Invalid journal ID format' });
        }

        const journal = await Journal.findById(req.params.id);
        if (!journal) {
            console.error('Journal not found:', req.params.id);
            return res.status(404).json({ message: 'Journal not found' });
        }

        console.log('Journal file URL from database:', journal.fileUrl);
        const filePath = path.join(__dirname, 'public', journal.fileUrl);
        console.log('Attempting to access file at:', filePath);

        if (!fs.existsSync(filePath)) {
            console.error('File not found at path:', filePath);
            // List contents of the uploads directory to help debug
            try {
                const files = fs.readdirSync(path.join(__dirname, 'public', 'uploads'));
                console.log('Contents of uploads directory:', files);
            } catch (dirError) {
                console.error('Error reading uploads directory:', dirError);
            }
            return res.status(404).json({ message: 'File not found' });
        }

        // Get file stats
        const stats = fs.statSync(filePath);
        if (stats.size === 0) {
            return res.status(400).json({ message: 'File is empty' });
        }

        console.log('File found, size:', stats.size, 'bytes');

        // Set appropriate headers
        const fileExtension = path.extname(journal.fileUrl).toLowerCase();
        let contentType = 'application/octet-stream';
        if (fileExtension === '.pdf') {
            contentType = 'application/pdf';
        } else if (fileExtension === '.doc') {
            contentType = 'application/msword';
        } else if (fileExtension === '.docx') {
            contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        }

        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Length', stats.size);
        res.setHeader('Content-Disposition', `attachment; filename="${path.basename(journal.fileUrl)}"`);
        
        // Stream the file
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
    } catch (error) {
        console.error('Error retrieving file:', error);
        res.status(500).json({ message: 'Error retrieving file: ' + error.message });
    }
});

// View journal file
app.get('/api/journals/:id/view', async (req, res) => {
    try {
        const journal = await Journal.findById(req.params.id);
        if (!journal) {
            console.error('Journal not found:', req.params.id);
            return res.status(404).json({ message: 'Journal not found' });
        }

        console.log('Journal file URL:', journal.fileUrl);
        const filePath = path.join(__dirname, 'public', journal.fileUrl);
        console.log('Full file path:', filePath);

        if (!fs.existsSync(filePath)) {
            console.error('File not found at path:', filePath);
            return res.status(404).json({ message: 'File not found' });
        }

        // Set appropriate headers for viewing
        const fileExtension = path.extname(journal.fileUrl).toLowerCase();
        let contentType = 'application/pdf';
        if (fileExtension === '.doc') {
            contentType = 'application/msword';
        } else if (fileExtension === '.docx') {
            contentType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
        }

        res.setHeader('Content-Type', contentType);
        res.setHeader('Content-Disposition', 'inline');
        
        // Stream the file
        const fileStream = fs.createReadStream(filePath);
        fileStream.pipe(res);
    } catch (error) {
        console.error('Error retrieving file:', error);
        res.status(500).json({ message: 'Error retrieving file: ' + error.message });
    }
});

// Google OAuth Routes
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, picture, sub: googleId } = payload;

        // Check if user exists
        let user = await User.findOne({ email });

        if (!user) {
            // Create new user if doesn't exist
            user = new User({
                name,
                email,
                googleId,
                profilePhoto: picture,
                isVerified: true
            });
            await user.save();
        }

        // Return user data
        res.json({
            message: 'Login successful',
            user: {
                name: user.name,
                email: user.email,
                profilePhoto: user.profilePhoto
            }
        });
    } catch (error) {
        console.error('Google auth error:', error);
        res.status(500).json({ message: 'Error authenticating with Google' });
    }
});

// Update the resend PIN endpoint
app.post('/api/auth/resend-pin', async (req, res) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate new PIN
        const verificationPin = Math.floor(100000 + Math.random() * 900000).toString();
        const pinExpiry = new Date(Date.now() + 10 * 60 * 1000); // PIN expires in 10 minutes

        // Update user with new PIN
        user.verificationPin = verificationPin;
        user.pinExpiry = pinExpiry;
        await user.save();

        // Send new verification email using the new email configuration
        await sendEmail(email, 'verification', {
            name: user.name,
            pin: verificationPin
        });

        res.json({ message: 'New PIN sent successfully' });
    } catch (error) {
        console.error('Resend PIN error:', error);
        res.status(500).json({ message: 'Error sending new PIN' });
    }
});

// Add password reset request endpoint
app.post('/api/auth/request-password-reset', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetExpiry = new Date(Date.now() + 3600000); // 1 hour

        // Update user with reset token
        user.resetToken = resetToken;
        user.resetExpiry = resetExpiry;
        await user.save();

        // Create reset link
        const resetLink = `${config.baseUrl}/reset-password?token=${resetToken}`;

        // Send password reset email
        await sendEmail(email, 'passwordReset', {
            name: user.name,
            resetLink
        });

        res.json({ message: 'Password reset email sent' });
    } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({ message: 'Error sending password reset email' });
    }
});

// Add password history check
userSchema.methods.checkPasswordHistory = async function(newPassword) {
    const passwordHistory = this.passwordHistory || [];
    for (const oldHash of passwordHistory) {
        if (await bcrypt.compare(newPassword, oldHash)) {
            return false;
        }
    }
    return true;
};

// Add test endpoint
app.get('/api/test', (req, res) => {
    res.json({ message: 'Server is running', timestamp: new Date() });
});

// Add update profile endpoint
app.put('/api/auth/update-profile', async (req, res) => {
    try {
        const { name, email, currentPassword, newPassword } = req.body;

        // Find user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Verify current password
        const isValidPassword = await bcrypt.compare(currentPassword, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }

        // Update user data
        user.name = name;

        // If new password is provided, update it
        if (newPassword) {
            // Check if new password is different from current
            const isSamePassword = await bcrypt.compare(newPassword, user.password);
            if (isSamePassword) {
                return res.status(400).json({ message: 'New password must be different from current password' });
            }

            // Check password history
            const isInHistory = await user.checkPasswordHistory(newPassword);
            if (!isInHistory) {
                return res.status(400).json({ message: 'New password must be different from your last 3 passwords' });
            }

            // Hash new password
            const hashedPassword = await bcrypt.hash(newPassword, 10);

            // Update password history
            user.passwordHistory = user.passwordHistory || [];
            user.passwordHistory.push(user.password);
            if (user.passwordHistory.length > 3) {
                user.passwordHistory.shift(); // Keep only last 3 passwords
            }

            user.password = hashedPassword;
            user.lastPasswordChange = new Date();
        }

        await user.save();

        // Return updated user data (excluding sensitive information)
        res.json({
            message: 'Profile updated successfully',
            user: {
                name: user.name,
                email: user.email,
                journalCount: user.journalCount,
                registrationDate: user.registrationDate
            }
        });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Error updating profile' });
    }
});

// Update the profile photo upload endpoint
app.post('/api/auth/upload-photo', uploadPhoto.single('photo'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No photo uploaded' });
        }

        const user = await User.findOne({ email: req.body.email });
        if (!user) {
            // Delete the uploaded file if user not found
            fs.unlinkSync(req.file.path);
            return res.status(404).json({ message: 'User not found' });
        }

        // Delete old profile photo if exists
        if (user.profilePhoto) {
            const oldPhotoPath = path.join(__dirname, 'public', user.profilePhoto);
            if (fs.existsSync(oldPhotoPath)) {
                fs.unlinkSync(oldPhotoPath);
            }
        }

        // Update user's profile photo
        user.profilePhoto = `/uploads/${req.file.filename}`;
        await user.save();

        res.json({
            message: 'Profile photo updated successfully',
            photoUrl: user.profilePhoto
        });
    } catch (error) {
        console.error('Error uploading profile photo:', error);
        // Delete the uploaded file if there's an error
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ message: 'Error uploading profile photo' });
    }
});

// Add journal status update notification
app.put('/api/journals/:id/status', async (req, res) => {
    try {
        const { status } = req.body;
        const journal = await Journal.findById(req.params.id);
        
        if (!journal) {
            return res.status(404).json({ message: 'Journal not found' });
        }

        journal.status = status;
        await journal.save();

        // Send status update email to authors
        for (const authorName of journal.authors) {
            const author = await User.findOne({ name: authorName });
            if (author) {
                await sendEmail(author.email, 'journalStatusUpdate', {
                    name: author.name,
                    journalTitle: journal.title,
                    status
                });
            }
        }

        res.json({ message: 'Status updated successfully' });
    } catch (error) {
        console.error('Error updating journal status:', error);
        res.status(500).json({ message: 'Error updating journal status' });
    }
});

// Add user verification endpoint (for testing purposes)
app.get('/api/admin/verify-user/:email', async (req, res) => {
    try {
        const { email } = req.params;
        
        // Find user and exclude sensitive data
        const user = await User.findOne({ email }).select('-password -passwordHistory -resetToken -resetExpiry');
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Get user's journals
        const journals = await Journal.find({ authors: user.name })
            .select('title status uploadDate')
            .sort({ uploadDate: -1 });

        res.json({
            user: {
                name: user.name,
                email: user.email,
                registrationDate: user.registrationDate,
                journalCount: user.journalCount,
                profilePhoto: user.profilePhoto,
                isVerified: user.isVerified,
                accountLocked: user.accountLocked
            },
            journals: journals
        });
    } catch (error) {
        console.error('Error verifying user:', error);
        res.status(500).json({ message: 'Error verifying user' });
    }
});

// Add user registration verification endpoint
app.post('/api/auth/verify-registration', async (req, res) => {
    try {
        const { email, pin } = req.body;
        
        const user = await User.findOne({ 
            email,
            verificationPin: pin,
            pinExpiry: { $gt: new Date() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired PIN' });
        }

        // Update user verification status
        user.isVerified = true;
        user.verificationPin = undefined;
        user.pinExpiry = undefined;
        await user.save();

        res.json({ 
            message: 'Email verified successfully',
            user: {
                name: user.name,
                email: user.email,
                isVerified: true
            }
        });
    } catch (error) {
        console.error('Error verifying registration:', error);
        res.status(500).json({ message: 'Error verifying registration' });
    }
});

// Add sample journals endpoint
app.post('/api/populate-journals', async (req, res) => {
    try {
        // Check database connection
        if (mongoose.connection.readyState !== 1) {
            return res.status(503).json({ message: 'Database connection not ready' });
        }

        // Sample journal data
        const sampleJournals = [
            {
                title: "The Impact of Technology on Modern Education",
                category: "Educational Technology",
                description: "This research paper explores how digital technologies are transforming traditional educational methods and improving student engagement and learning outcomes.",
                authors: ["Dr. Sarah Johnson", "Prof. Michael Chen"],
                editors: ["Dr. Emily Rodriguez"],
                associateEditors: ["Prof. David Kim"],
                fileUrl: "sample-journal-1.pdf",
                views: 150,
                downloads: 45,
                citations: 12
            },
            {
                title: "Innovative Teaching Methods in STEM Education",
                category: "STEM Education",
                description: "A comprehensive study on implementing project-based learning and hands-on activities in science, technology, engineering, and mathematics classrooms.",
                authors: ["Dr. Robert Williams", "Dr. Lisa Thompson"],
                editors: ["Prof. James Anderson"],
                associateEditors: ["Dr. Maria Garcia"],
                fileUrl: "sample-journal-2.pdf",
                views: 89,
                downloads: 23,
                citations: 8
            },
            {
                title: "The Role of Emotional Intelligence in Student Success",
                category: "Psychology in Education",
                description: "This paper examines how emotional intelligence skills contribute to academic achievement and social development in students.",
                authors: ["Dr. Jennifer Davis", "Prof. Thomas Wilson"],
                editors: ["Dr. Amanda Brown"],
                associateEditors: ["Prof. Christopher Lee"],
                fileUrl: "sample-journal-3.pdf",
                views: 203,
                downloads: 67,
                citations: 19
            },
            {
                title: "Digital Literacy in the 21st Century Classroom",
                category: "Digital Education",
                description: "An analysis of digital literacy skills required for students to succeed in the modern digital world and how educators can foster these skills.",
                authors: ["Dr. Patricia Martinez", "Dr. Kevin Taylor"],
                editors: ["Prof. Rachel Green"],
                associateEditors: ["Dr. Steven White"],
                fileUrl: "sample-journal-4.pdf",
                views: 134,
                downloads: 38,
                citations: 15
            },
            {
                title: "Inclusive Education: Strategies for Diverse Classrooms",
                category: "Special Education",
                description: "This research presents effective strategies for creating inclusive learning environments that accommodate students with diverse learning needs.",
                authors: ["Dr. Michelle Clark", "Prof. Daniel Lewis"],
                editors: ["Dr. Rebecca Hall"],
                associateEditors: ["Prof. Andrew Scott"],
                fileUrl: "sample-journal-5.pdf",
                views: 178,
                downloads: 52,
                citations: 11
            }
        ];

        // Clear existing journals
        await Journal.deleteMany({});
        console.log('Cleared existing journals');

        // Add sample journals
        const result = await Journal.insertMany(sampleJournals);
        console.log(`Successfully added ${result.length} sample journals`);

        res.json({ 
            message: `Successfully added ${result.length} sample journals`,
            journals: result.map(j => ({ id: j._id, title: j.title, category: j.category }))
        });
    } catch (error) {
        console.error('Error populating journals:', error);
        res.status(500).json({ 
            message: 'Error populating journals',
            error: process.env.NODE_ENV === 'development' ? error.message : 'Internal server error'
        });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    console.error('Error stack:', err.stack);
    
    // Check if it's a MongoDB connection error
    if (err.name === 'MongoServerError' || err.name === 'MongooseError') {
        return res.status(503).json({
            message: 'Database connection error. Please try again later.',
            error: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
    
    res.status(500).json({ 
        message: err.message || 'Something went wrong!',
        error: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
});

// Update the server start code at the bottom
const startServer = () => {
    const port = process.env.PORT || 3000;
    app.listen(port, () => {
        console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${port}`);
        console.log(`Upload directory: ${uploadsDir}`);
    }).on('error', (err) => {
        console.error('Server error:', err);
        process.exit(1);
    });
};

// Only start the server if we're not in a serverless environment
if (process.env.NODE_ENV !== 'production') {
    startServer();
}

// Export the Express app for Vercel
module.exports = app;

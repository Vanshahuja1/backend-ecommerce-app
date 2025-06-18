const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb+srv://pooja:123@cluster0.vs62poi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
mongoose.connection.on('connected', () => {
  console.log('MongoDB connected successfully');
});

// User Schema - Updated with admin role and seller request status
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userType: { type: String, enum: ['buyer', 'seller', 'admin'], default: 'buyer' },
  profileImage: { type: String },
  storeName: { type: String },
  storeAddress: { type: String },
  businessLicense: { type: String },
  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  sellerRequestStatus: { type: String, enum: ['none', 'pending', 'approved', 'rejected'], default: 'none' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const sellerRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true },
  storeName: { type: String, required: true },
  storeAddress: { type: String, required: true },
  businessLicense: { type: String },
  status: { type: String, enum: ['pending', 'approved', 'rejected'], default: 'pending' },
  requestedAt: { type: Date, default: Date.now },
  processedAt: { type: Date },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  rejectionReason: { type: String },
  createdAt: { type: Date, default: Date.now }
});

const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  imageUrl: { type: String },
  quantity: { type: Number, required: true },
  unit: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sellerName: { type: String, required: true },
  storeName: { type: String },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  token: { type: String },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const SellerRequest = mongoose.model('SellerRequest', sellerRequestSchema);
const Item = mongoose.model('Item', itemSchema);
const OTP = mongoose.model('OTP', otpSchema);

// Configure email transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user || user.userType !== 'admin') {
      return res.status(403).json({ 
        success: false, 
        message: 'Admin access required' 
      });
    }
    next();
  } catch (error) {
    return res.status(500).json({ 
      success: false, 
      message: 'Error verifying admin status' 
    });
  }
};

// Generate a 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ============================
// User Info Update API (NEW)
// ============================
app.put('/api/user/update-info', authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body;
    if (!name && !phone) {
      return res.status(400).json({ success: false, message: 'Nothing to update' });
    }
    // Check if phone is being updated and is unique
    if (phone) {
      const phoneExists = await User.findOne({ phone, _id: { $ne: req.user.id } });
      if (phoneExists) {
        return res.status(400).json({ success: false, message: 'Phone number already exists.' });
      }
    }
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    if (name) user.name = name;
    if (phone) user.phone = phone;
    user.updatedAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: 'User information updated successfully',
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        userType: user.userType
      }
    });
  } catch (error) {
    console.error('Update info error:', error);
    res.status(500).json({ success: false, message: 'Failed to update user info' });
  }
});

// ==============================
// Nodemailer Signup Email (NEW)
// ==============================
async function sendSignupMail({ name, email, phone }) {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Welcome to Our Platform!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #333; text-align: center;">Welcome, ${name}!</h2>
        <p>Thank you for signing up at our platform. Here are your registration details:</p>
        <ul>
          <li><b>Name:</b> ${name}</li>
          <li><b>Email:</b> ${email}</li>
          <li><b>Phone:</b> ${phone}</li>
        </ul>
        <p>We're excited to have you on board!</p>
        <p style="margin-top: 30px; font-size: 12px; color: #777; text-align: center;">
          This is an automated email. Please do not reply.
        </p>
      </div>
    `,
  };
  await transporter.sendMail(mailOptions);
}

// Register User (UPDATED)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, phone, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { phone }] 
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email or phone number.'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      userType: 'buyer'
    });

    await user.save();

    // Send welcome mail with user details
    try {
      await sendSignupMail({ name, email, phone });
    } catch (mailErr) {
      console.error('Signup email send error:', mailErr);
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    // Return user data without password
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      userType: user.userType,
      profileImage: user.profileImage,
      createdAt: user.createdAt
    };

    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      user: userData,
      token
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during signup. Please try again.'
    });
  }
});

// ========== (rest of your routes remain unchanged) ==========

// Send OTP for password reset
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email is required' 
      });
    }
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'No user found with this email address' 
      });
    }
    
    const otp = generateOTP();
    const expiresAt = new Date();
    expiresAt.setMinutes(expiresAt.getMinutes() + 15);
    await OTP.deleteMany({ email });
    const otpDoc = new OTP({
      email,
      otp,
      expiresAt
    });
    await otpDoc.save();
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Password Reset OTP',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #333; text-align: center;">Password Reset</h2>
          <p>Hello ${user.name},</p>
          <p>You requested to reset your password. Please use the following OTP to verify your identity:</p>
          <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${otp}
          </div>
          <p>This OTP will expire in 15 minutes.</p>
          <p>If you didn't request this password reset, please ignore this email or contact support if you have concerns.</p>
          <p style="margin-top: 30px; font-size: 12px; color: #777; text-align: center;">
            This is an automated email. Please do not reply.
          </p>
        </div>
      `,
    };
    await transporter.sendMail(mailOptions);
    res.status(200).json({ 
      success: true, 
      message: 'OTP sent to your email address' 
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred while processing your request' 
    });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email and OTP are required' 
      });
    }
    const otpDoc = await OTP.findOne({ email, otp });
    if (!otpDoc) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid OTP' 
      });
    }
    if (new Date() > otpDoc.expiresAt) {
      await OTP.deleteOne({ _id: otpDoc._id });
      return res.status(400).json({ 
        success: false, 
        error: 'OTP has expired' 
      });
    }
    const token = crypto.randomBytes(32).toString('hex');
    otpDoc.token = token;
    otpDoc.expiresAt = new Date();
    otpDoc.expiresAt.setMinutes(otpDoc.expiresAt.getMinutes() + 30);
    await otpDoc.save();
    res.status(200).json({ 
      success: true, 
      message: 'OTP verified successfully', 
      token 
    });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred while verifying OTP' 
    });
  }
});

// Reset password with token
app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, token, password } = req.body;
    if (!email || !token || !password) {
      return res.status(400).json({ 
        success: false, 
        error: 'Email, token and password are required' 
      });
    }
    const otpDoc = await OTP.findOne({ email, token });
    if (!otpDoc) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid or expired token' 
      });
    }
    if (new Date() > otpDoc.expiresAt) {
      await OTP.deleteOne({ _id: otpDoc._id });
      return res.status(400).json({ 
        success: false, 
        error: 'Reset token has expired' 
      });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        error: 'User not found' 
      });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    user.password = hashedPassword;
    user.updatedAt = new Date();
    await user.save();
    await OTP.deleteOne({ _id: otpDoc._id });
    res.status(200).json({ 
      success: true, 
      message: 'Password reset successfully' 
    });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      success: false, 
      error: 'An error occurred while resetting password' 
    });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;
    const user = await User.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }]
    });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials. Please check your email/phone and password.'
      });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials. Please check your email/phone and password.'
      });
    }
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      userType: user.userType,
      profileImage: user.profileImage,
      storeName: user.storeName,
      storeAddress: user.storeAddress,
      isVerified: user.isVerified,
      isActive: user.isActive,
      createdAt: user.createdAt
    };
    res.json({
      success: true,
      message: 'Login successful!',
      user: userData,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'An error occurred during login. Please try again.'
    });
  }
});

// Get Current User
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      userType: user.userType,
      profileImage: user.profileImage,
      storeName: user.storeName,
      storeAddress: user.storeAddress,
      businessLicense: user.businessLicense,
      isVerified: user.isVerified,
      isActive: user.isActive,
      sellerRequestStatus: user.sellerRequestStatus,
      createdAt: user.createdAt
    };
    res.json({
      success: true,
      user: userData
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to get user data'
    });
  }
});

// Become Seller - Updated to create seller request instead of direct conversion
app.post('/api/auth/become-seller', authenticateToken, async (req, res) => {
  try {
    const { storeName, storeAddress, businessLicense } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Check if user already has a pending or approved request
    const existingRequest = await SellerRequest.findOne({
      userId: user._id,
      status: { $in: ['pending', 'approved'] }
    });

    if (existingRequest) {
      return res.status(400).json({
        success: false,
        message: `You already have a ${existingRequest.status} seller request.`
      });
    }

    if (user.userType === 'seller') {
      return res.status(400).json({
        success: false,
        message: 'You are already a seller.'
      });
    }

    // Create seller request
    const sellerRequest = new SellerRequest({
      userId: user._id,
      userName: user.name,
      userEmail: user.email,
      storeName,
      storeAddress,
      businessLicense
    });

    await sellerRequest.save();

    // Update user status
    user.sellerRequestStatus = 'pending';
    user.updatedAt = new Date();
    await user.save();

    res.json({
      success: true,
      message: 'Seller request submitted successfully! Please wait for admin approval.',
      request: {
        id: sellerRequest._id,
        status: sellerRequest.status,
        createdAt: sellerRequest.createdAt
      }
    });

  } catch (error) {
    console.error('Become seller error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to submit seller request. Please try again.'
    });
  }
});

// =============================================================================
// ADMIN ROUTES
// =============================================================================

// Get Admin Dashboard Stats
app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments({ userType: { $ne: 'admin' } });
    const totalSellers = await User.countDocuments({ userType: 'seller' });
    const pendingRequests = await SellerRequest.countDocuments({ status: 'pending' });
    const activeSellers = await User.countDocuments({ 
      userType: 'seller', 
      isActive: true 
    });

    const stats = {
      totalUsers,
      totalSellers,
      pendingRequests,
      activeSellers
    };

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    console.error('Get admin stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch admin statistics'
    });
  }
});

// Get Seller Requests
app.get('/api/admin/seller-requests', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    let query = {};
    if (status) {
      query.status = status;
    }

    const requests = await SellerRequest.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .populate('userId', 'name email phone')
      .populate('processedBy', 'name email');

    const total = await SellerRequest.countDocuments(query);

    res.json({
      success: true,
      requests,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalRequests: total
    });

  } catch (error) {
    console.error('Get seller requests error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch seller requests'
    });
  }
});

// Approve Seller Request
app.post('/api/admin/seller-requests/:id/approve', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    const adminId = req.user.id;

    const sellerRequest = await SellerRequest.findById(requestId);
    if (!sellerRequest) {
      return res.status(404).json({
        success: false,
        message: 'Seller request not found'
      });
    }

    if (sellerRequest.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'This request has already been processed'
      });
    }

    // Update seller request
    sellerRequest.status = 'approved';
    sellerRequest.processedAt = new Date();
    sellerRequest.processedBy = adminId;
    await sellerRequest.save();

    // Update user to seller
    const user = await User.findById(sellerRequest.userId);
    if (user) {
      user.userType = 'seller';
      user.storeName = sellerRequest.storeName;
      user.storeAddress = sellerRequest.storeAddress;
      user.businessLicense = sellerRequest.businessLicense;
      user.sellerRequestStatus = 'approved';
      user.isVerified = true;
      user.updatedAt = new Date();
      await user.save();
    }

    res.json({
      success: true,
      message: 'Seller request approved successfully',
      request: sellerRequest
    });

  } catch (error) {
    console.error('Approve seller request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to approve seller request'
    });
  }
});

// Reject Seller Request
app.post('/api/admin/seller-requests/:id/reject', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const requestId = req.params.id;
    const adminId = req.user.id;
    const { reason } = req.body;

    const sellerRequest = await SellerRequest.findById(requestId);
    if (!sellerRequest) {
      return res.status(404).json({
        success: false,
        message: 'Seller request not found'
      });
    }

    if (sellerRequest.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'This request has already been processed'
      });
    }

    // Update seller request
    sellerRequest.status = 'rejected';
    sellerRequest.processedAt = new Date();
    sellerRequest.processedBy = adminId;
    sellerRequest.rejectionReason = reason;
    await sellerRequest.save();

    // Update user status
    const user = await User.findById(sellerRequest.userId);
    if (user) {
      user.sellerRequestStatus = 'rejected';
      user.updatedAt = new Date();
      await user.save();
    }

    res.json({
      success: true,
      message: 'Seller request rejected successfully',
      request: sellerRequest
    });

  } catch (error) {
    console.error('Reject seller request error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to reject seller request'
    });
  }
});

// Get All Sellers
app.get('/api/admin/sellers', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, status } = req.query;
    
    let query = { userType: 'seller' };
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { storeName: { $regex: search, $options: 'i' } }
      ];
    }

    if (status) {
      query.isActive = status === 'active';
    }

    const sellers = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      sellers,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalSellers: total
    });

  } catch (error) {
    console.error('Get sellers error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch sellers'
    });
  }
});

// Toggle Seller Status (Activate/Deactivate)
app.patch('/api/admin/sellers/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const sellerId = req.params.id;
    const { isActive } = req.body;

    const seller = await User.findOne({ 
      _id: sellerId, 
      userType: 'seller' 
    });

    if (!seller) {
      return res.status(404).json({
        success: false,
        message: 'Seller not found'
      });
    }

    seller.isActive = isActive;
    seller.updatedAt = new Date();
    await seller.save();

    // If deactivating, also deactivate all their items
    if (!isActive) {
      await Item.updateMany(
        { sellerId: sellerId },
        { isAvailable: false, updatedAt: new Date() }
      );
    }

    res.json({
      success: true,
      message: `Seller ${isActive ? 'activated' : 'deactivated'} successfully`,
      seller: {
        id: seller._id,
        name: seller.name,
        email: seller.email,
        isActive: seller.isActive
      }
    });

  } catch (error) {
    console.error('Toggle seller status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update seller status'
    });
  }
});

// Get All Users (for admin)
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search, userType } = req.query;
    
    let query = { userType: { $ne: 'admin' } };
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }

    if (userType && userType !== 'all') {
      query.userType = userType;
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    res.json({
      success: true,
      users,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page),
      totalUsers: total
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch users'
    });
  }
});

// Create Admin User (Run this once to create your first admin)
app.post('/api/create-admin', async (req, res) => {
  try {
    const { name, email, phone, password, secretKey } = req.body;

    // Use a secret key to protect this endpoint
    if (secretKey !== 'create-admin-secret-2024') {
      return res.status(401).json({
        success: false,
        message: 'Invalid secret key'
      });
    }

    // Check if admin already exists
    const existingAdmin = await User.findOne({ userType: 'admin' });
    if (existingAdmin) {
      return res.status(400).json({
        success: false,
        message: 'Admin user already exists'
      });
    }

    // Check if user with email/phone already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { phone }] 
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User already exists with this email or phone number.'
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create admin user
    const admin = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      userType: 'admin',
      isVerified: true
    });

    await admin.save();

    res.status(201).json({
      success: true,
      message: 'Admin user created successfully!',
      admin: {
        id: admin._id,
        name: admin.name,
        email: admin.email,
        userType: admin.userType
      }
    });

  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create admin user'
    });
  }
});
// Toggle User Status (Activate/Deactivate) - For admin
app.patch('/api/admin/users/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { isActive } = req.body;

    // Prevent admin from changing their own status or other admins
    const user = await User.findOne({ _id: userId, userType: { $ne: 'admin' } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found or you cannot modify admin status'
      });
    }

    user.isActive = isActive;
    user.updatedAt = new Date();
    await user.save();

    // If user is a seller, also update their items' isAvailable status
    if (user.userType === 'seller') {
      await Item.updateMany(
        { sellerId: userId },
        { isAvailable: !!isActive, updatedAt: new Date() }
      );
    }

    res.json({
      success: true,
      message: `User ${isActive ? 'activated' : 'deactivated'} successfully`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        isActive: user.isActive,
        userType: user.userType
      }
    });

  } catch (error) {
    console.error('Toggle user status error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update user status'
    });
  }
});
// =============================================================================
// EXISTING ROUTES (Updated for new seller flow)
// =============================================================================

// Add Item (Sellers only) - Updated to check seller status
app.post('/api/items', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user || user.userType !== 'seller') {
      return res.status(403).json({
        success: false,
        message: 'Only approved sellers can add items'
      });
    }

    if (!user.isActive) {
      return res.status(403).json({
        success: false,
        message: 'Your seller account is currently deactivated. Please contact admin.'
      });
    }

    const { name, description, price, category, imageUrl, quantity, unit } = req.body;

    const item = new Item({
      name,
      description,
      price,
      category,
      imageUrl,
      quantity,
      unit,
      sellerId: user._id,
      sellerName: user.name,
      storeName: user.storeName || user.name
    });

    await item.save();

    res.status(201).json({
      success: true,
      message: 'Item added successfully!',
      item
    });

  } catch (error) {
    console.error('Add item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to add item. Please try again.'
    });
  }
});

// Get All Items - Updated to only show items from active sellers
app.get('/api/items', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 20 } = req.query;
    
    // First get active sellers
    const activeSellers = await User.find({ 
      userType: 'seller', 
      isActive: true 
    }).select('_id');
    
    const activeSellerIds = activeSellers.map(seller => seller._id);
    
    let query = { 
      isAvailable: true,
      sellerId: { $in: activeSellerIds }
    };
    
    if (category) {
      query.category = category;
    }
    
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { description: { $regex: search, $options: 'i' } },
        { category: { $regex: search, $options: 'i' } }
      ];
    }

    const items = await Item.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Item.countDocuments(query);

    res.json({
      success: true,
      items,
      totalPages: Math.ceil(total / limit),
      currentPage: page,
      totalItems: total
    });

  } catch (error) {
    console.error('Get items error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch items'
    });
  }
});

// Get Seller Items
app.get('/api/items/my-items', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user || user.userType !== 'seller') {
      return res.status(403).json({
        success: false,
        message: 'Only sellers can view their items'
      });
    }

    const items = await Item.find({ sellerId: user._id })
      .sort({ createdAt: -1 });

    res.json({
      success: true,
      items
    });

  } catch (error) {
    console.error('Get seller items error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch your items'
    });
  }
});

// Update Item
app.put('/api/items/:id', authenticateToken, async (req, res) => {
  try {
    const item = await Item.findOne({ 
      _id: req.params.id, 
      sellerId: req.user.id 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found or you are not authorized to update it'
      });
    }

    const updates = req.body;
    updates.updatedAt = new Date();

    const updatedItem = await Item.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    );

    res.json({
      success: true,
      message: 'Item updated successfully!',
      item: updatedItem
    });

  } catch (error) {
    console.error('Update item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to update item'
    });
  }
});

// Delete Item
app.delete('/api/items/:id', authenticateToken, async (req, res) => {
  try {
    const item = await Item.findOneAndDelete({ 
      _id: req.params.id, 
      sellerId: req.user.id 
    });

    if (!item) {
      return res.status(404).json({
        success: false,
        message: 'Item not found or you are not authorized to delete it'
      });
    }

    res.json({
      success: true,
      message: 'Item deleted successfully!'
    });

  } catch (error) {
    console.error('Delete item error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to delete item'
    });
  }
});

// Get Categories
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Item.distinct('category');
    
    res.json({
      success: true,
      categories
    });

  } catch (error) {
    console.error('Get categories error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch categories'
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log('\n=== ADMIN SETUP ===');
  console.log('To create your first admin user, make a POST request to:');
  console.log(`http://your-server:${PORT}/api/create-admin`);
  console.log('With body: { "name": "Admin Name", "email": "admin@example.com", "phone": "1234567890", "password": "adminpass", "secretKey": "create-admin-secret-2024" }');
  console.log('==================\n');
});

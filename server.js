const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
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
// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userType: { type: String, enum: ['buyer', 'seller'], default: 'buyer' },
  profileImage: { type: String },
  // Seller specific fields
  storeName: { type: String },
  storeAddress: { type: String },
  businessLicense: { type: String },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Item Schema
const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  imageUrl: { type: String },
  quantity: { type: Number, required: true },
  unit: { type: String, required: true }, // kg, pieces, liters, etc.
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  sellerName: { type: String, required: true },
  storeName: { type: String },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Item = mongoose.model('Item', itemSchema);

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

// Routes

// Register User
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

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body;

    // Find user by email or phone
    const user = await User.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }]
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials. Please check your email/phone and password.'
      });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Invalid credentials. Please check your email/phone and password.'
      });
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
      storeName: user.storeName,
      storeAddress: user.storeAddress,
      isVerified: user.isVerified,
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

// Become Seller
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

    // Update user to seller
    user.userType = 'seller';
    user.storeName = storeName;
    user.storeAddress = storeAddress;
    user.businessLicense = businessLicense;
    user.updatedAt = new Date();

    await user.save();

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
      createdAt: user.createdAt
    };

    res.json({
      success: true,
      message: 'Successfully became a seller!',
      user: userData
    });

  } catch (error) {
    console.error('Become seller error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to become seller. Please try again.'
    });
  }
});

// Add Item (Sellers only)
app.post('/api/items', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user || user.userType !== 'seller') {
      return res.status(403).json({
        success: false,
        message: 'Only sellers can add items'
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

// Get All Items
app.get('/api/items', async (req, res) => {
  try {
    const { category, search, page = 1, limit = 20 } = req.query;
    
    let query = { isAvailable: true };
    
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

const PORT = 3000;
app.listen(3000, '0.0.0.0', () => console.log('Server running on port 3000'));



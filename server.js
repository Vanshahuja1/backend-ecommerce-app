const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const nodemailer = require("nodemailer")
const crypto = require("crypto")
// const Razorpay = require('razorpay'); // Commented for development
require("dotenv").config()

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Initialize Razorpay - Commented for development
/*
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});
*/

// MongoDB Connection
mongoose.connect(
  process.env.MONGODB_URI ||
    "mongodb+srv://pooja:123@cluster0.vs62poi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  },
)
mongoose.connection.on("connected", () => {
  console.log("MongoDB connected successfully")
})

// Cart Schema - NEW
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  items: [
    {
      productId: { type: String, required: true }, // Can be ObjectId or string
      name: { type: String, required: true },
      price: { type: Number, required: true },
      imageUrl: { type: String },
      category: { type: String },
      unit: { type: String, required: true },
      quantity: { type: Number, required: true, min: 1 },
      addedAt: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

// Create compound index for efficient queries
cartSchema.index({ userId: 1 })
cartSchema.index({ userId: 1, "items.productId": 1 })

// Address Schema
const addressSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true }, // Home, Office, etc.
  name: { type: String, required: true },
  phone: { type: String, required: true },
  address: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  pincode: { type: String, required: true },
  isDefault: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  orderId: { type: String, unique: true, required: true },
  items: [
    {
      itemId: { type: mongoose.Schema.Types.ObjectId, ref: "Item" },
      name: { type: String, required: true },
      price: { type: Number, required: true },
      quantity: { type: Number, required: true },
      sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      sellerName: { type: String },
    },
  ],
  address: {
    name: { type: String, required: true },
    phone: { type: String, required: true },
    address: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
  },
  paymentMethod: { type: String, enum: ["cod", "online"], required: true },
  paymentStatus: { type: String, enum: ["pending", "paid", "failed", "refunded"], default: "pending" },
  paymentId: { type: String }, // Razorpay payment ID
  razorpayOrderId: { type: String }, // Razorpay order ID
  subtotal: { type: Number, required: true },
  deliveryFee: { type: Number, required: true },
  taxAmount: { type: Number, required: true },
  totalAmount: { type: Number, required: true },
  orderStatus: {
    type: String,
    enum: ["pending", "confirmed", "processing", "shipped", "delivered", "cancelled"],
    default: "pending",
  },
  estimatedDelivery: { type: Date },
  deliveredAt: { type: Date },
  cancelledAt: { type: Date },
  cancellationReason: { type: String },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

// User Schema - Updated with address reference
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  userType: { type: String, enum: ["buyer", "seller", "admin"], default: "buyer" },
  profileImage: { type: String },
  storeName: { type: String },
  storeAddress: { type: String },
  businessLicense: { type: String },
  isVerified: { type: Boolean, default: false },
  isActive: { type: Boolean, default: true },
  sellerRequestStatus: { type: String, enum: ["none", "pending", "approved", "rejected"], default: "none" },
  // Address fields removed from user schema as we now have separate Address model
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

const sellerRequestSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true },
  storeName: { type: String, required: true },
  storeAddress: { type: String, required: true },
  businessLicense: { type: String },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
  requestedAt: { type: Date, default: Date.now },
  processedAt: { type: Date },
  processedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  rejectionReason: { type: String },
  createdAt: { type: Date, default: Date.now },
})

const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  price: { type: Number, required: true },
  category: { type: String, required: true },
  imageUrl: { type: String },
  quantity: { type: Number, required: true },
  unit: { type: String, required: true },
  sellerId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  sellerName: { type: String, required: true },
  storeName: { type: String },
  isAvailable: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
})

const otpSchema = new mongoose.Schema({
  email: { type: String, required: true },
  otp: { type: String, required: true },
  token: { type: String },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
})

// Models
const User = mongoose.model("User", userSchema)
const Cart = mongoose.model("Cart", cartSchema) // NEW
const Address = mongoose.model("Address", addressSchema)
const Order = mongoose.model("Order", orderSchema)
const SellerRequest = mongoose.model("SellerRequest", sellerRequestSchema)
const Item = mongoose.model("Item", itemSchema)
const OTP = mongoose.model("OTP", otpSchema)

// Configure email transporter
const transporter = nodemailer.createTransporter({
  service: process.env.EMAIL_SERVICE || "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD,
  },
})

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"]
  const token = authHeader && authHeader.split(" ")[1]

  if (!token) {
    return res.status(401).json({ success: false, message: "Access token required" })
  }

  jwt.verify(token, process.env.JWT_SECRET || "your-secret-key", (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: "Invalid token" })
    }
    req.user = user
    next()
  })
}

// Admin Middleware
const requireAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id)
    if (!user || user.userType !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required",
      })
    }
    next()
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Error verifying admin status",
    })
  }
}

// Generate a 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString()
}

// Generate unique order ID
function generateOrderId() {
  const timestamp = Date.now().toString()
  const random = Math.floor(Math.random() * 1000)
    .toString()
    .padStart(3, "0")
  return `ORD${timestamp}${random}`
}

// =============================================================================
// CART MANAGEMENT APIs - NEW
// =============================================================================

// Get user's cart items
app.get("/api/cart/:userId", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId

    // Verify user can only access their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    const cart = await Cart.findOne({ userId })

    if (!cart) {
      return res.json({
        success: true,
        cartItems: [],
        totalItems: 0,
        totalPrice: 0,
      })
    }

    // Calculate totals
    const totalItems = cart.items.reduce((sum, item) => sum + item.quantity, 0)
    const totalPrice = cart.items.reduce((sum, item) => sum + item.price * item.quantity, 0)

    res.json({
      success: true,
      cartItems: cart.items.map((item) => ({
        _id: item.productId,
        productId: item.productId,
        name: item.name,
        price: item.price,
        imageUrl: item.imageUrl,
        category: item.category,
        unit: item.unit,
        quantity: item.quantity,
        addedAt: item.addedAt,
      })),
      totalItems,
      totalPrice: Math.round(totalPrice * 100) / 100, // Round to 2 decimal places
    })
  } catch (error) {
    console.error("Get cart error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch cart items",
    })
  }
})

// Add item to user's cart
app.post("/api/cart/add", authenticateToken, async (req, res) => {
  try {
    const { userId, productId, name, price, imageUrl, category, unit, quantity = 1 } = req.body

    // Verify user can only modify their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    // Validate required fields
    if (!productId || !name || !price || !unit) {
      return res.status(400).json({
        success: false,
        message: "Product ID, name, price, and unit are required",
      })
    }

    // Find or create cart for user
    let cart = await Cart.findOne({ userId })

    if (!cart) {
      cart = new Cart({
        userId,
        items: [],
      })
    }

    // Check if item already exists in cart
    const existingItemIndex = cart.items.findIndex((item) => item.productId === productId)

    if (existingItemIndex > -1) {
      // Update quantity if item exists
      cart.items[existingItemIndex].quantity += quantity
      cart.items[existingItemIndex].addedAt = new Date()
    } else {
      // Add new item to cart
      cart.items.push({
        productId,
        name,
        price: Number.parseFloat(price),
        imageUrl: imageUrl || "",
        category: category || "",
        unit,
        quantity: Number.parseInt(quantity),
        addedAt: new Date(),
      })
    }

    cart.updatedAt = new Date()
    await cart.save()

    res.json({
      success: true,
      message: "Item added to cart successfully",
      cartItemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
    })
  } catch (error) {
    console.error("Add to cart error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to add item to cart",
    })
  }
})

// Remove item from user's cart
app.delete("/api/cart/remove", authenticateToken, async (req, res) => {
  try {
    const { userId, productId } = req.body

    // Verify user can only modify their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    const cart = await Cart.findOne({ userId })

    if (!cart) {
      return res.status(404).json({
        success: false,
        message: "Cart not found",
      })
    }

    // Find and remove the item
    const itemIndex = cart.items.findIndex((item) => item.productId === productId)

    if (itemIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Item not found in cart",
      })
    }

    cart.items.splice(itemIndex, 1)
    cart.updatedAt = new Date()

    // If cart is empty, you might want to delete the cart document
    if (cart.items.length === 0) {
      await Cart.deleteOne({ userId })
    } else {
      await cart.save()
    }

    res.json({
      success: true,
      message: "Item removed from cart successfully",
      cartItemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
    })
  } catch (error) {
    console.error("Remove from cart error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to remove item from cart",
    })
  }
})

// Update item quantity in user's cart
app.put("/api/cart/update", authenticateToken, async (req, res) => {
  try {
    const { userId, productId, quantity } = req.body

    // Verify user can only modify their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    if (!quantity || quantity < 1) {
      return res.status(400).json({
        success: false,
        message: "Quantity must be at least 1",
      })
    }

    const cart = await Cart.findOne({ userId })

    if (!cart) {
      return res.status(404).json({
        success: false,
        message: "Cart not found",
      })
    }

    // Find and update the item
    const itemIndex = cart.items.findIndex((item) => item.productId === productId)

    if (itemIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Item not found in cart",
      })
    }

    cart.items[itemIndex].quantity = Number.parseInt(quantity)
    cart.items[itemIndex].addedAt = new Date() // Update timestamp
    cart.updatedAt = new Date()

    await cart.save()

    res.json({
      success: true,
      message: "Cart updated successfully",
      cartItemCount: cart.items.reduce((sum, item) => sum + item.quantity, 0),
    })
  } catch (error) {
    console.error("Update cart error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to update cart",
    })
  }
})

// Clear user's entire cart
app.delete("/api/cart/clear/:userId", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId

    // Verify user can only modify their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    await Cart.deleteOne({ userId })

    res.json({
      success: true,
      message: "Cart cleared successfully",
      cartItemCount: 0,
    })
  } catch (error) {
    console.error("Clear cart error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to clear cart",
    })
  }
})

// Get cart item count for user (utility endpoint)
app.get("/api/cart/:userId/count", authenticateToken, async (req, res) => {
  try {
    const userId = req.params.userId

    // Verify user can only access their own cart
    if (req.user.id !== userId) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      })
    }

    const cart = await Cart.findOne({ userId })
    const count = cart ? cart.items.reduce((sum, item) => sum + item.quantity, 0) : 0

    res.json({
      success: true,
      count,
    })
  } catch (error) {
    console.error("Get cart count error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to get cart count",
    })
  }
})

// =============================================================================
// ADDRESS MANAGEMENT APIs
// =============================================================================

// Get user addresses
app.get("/api/addresses", authenticateToken, async (req, res) => {
  try {
    const addresses = await Address.find({ userId: req.user.id }).sort({ isDefault: -1, createdAt: -1 }).limit(3) // Limit to 3 addresses as per frontend

    res.json({
      success: true,
      addresses,
    })
  } catch (error) {
    console.error("Get addresses error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch addresses",
    })
  }
})

// Add new address
app.post("/api/addresses", authenticateToken, async (req, res) => {
  try {
    const { title, name, phone, address, city, state, pincode, isDefault } = req.body

    // Validate required fields
    if (!title || !name || !phone || !address || !city || !state || !pincode) {
      return res.status(400).json({
        success: false,
        message: "All address fields are required",
      })
    }

    // Validate pincode
    if (pincode.length !== 6) {
      return res.status(400).json({
        success: false,
        message: "Pincode must be 6 digits",
      })
    }

    // Validate phone
    if (phone.length < 10) {
      return res.status(400).json({
        success: false,
        message: "Phone number must be at least 10 digits",
      })
    }

    // Check if user already has 3 addresses
    const existingAddresses = await Address.countDocuments({ userId: req.user.id })
    if (existingAddresses >= 3) {
      return res.status(400).json({
        success: false,
        message: "Maximum 3 addresses allowed per user",
      })
    }

    // If this is set as default, remove default from other addresses
    if (isDefault) {
      await Address.updateMany({ userId: req.user.id }, { isDefault: false })
    }

    // If this is the first address, make it default
    const shouldBeDefault = existingAddresses === 0 || isDefault

    const newAddress = new Address({
      userId: req.user.id,
      title,
      name,
      phone,
      address,
      city,
      state,
      pincode,
      isDefault: shouldBeDefault,
    })

    await newAddress.save()

    res.status(201).json({
      success: true,
      message: "Address added successfully",
      address: newAddress,
    })
  } catch (error) {
    console.error("Add address error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to add address",
    })
  }
})

// Update address
app.put("/api/addresses/:id", authenticateToken, async (req, res) => {
  try {
    const addressId = req.params.id
    const { title, name, phone, address, city, state, pincode, isDefault } = req.body

    const existingAddress = await Address.findOne({
      _id: addressId,
      userId: req.user.id,
    })

    if (!existingAddress) {
      return res.status(404).json({
        success: false,
        message: "Address not found",
      })
    }

    // If setting as default, remove default from other addresses
    if (isDefault && !existingAddress.isDefault) {
      await Address.updateMany({ userId: req.user.id, _id: { $ne: addressId } }, { isDefault: false })
    }

    const updatedAddress = await Address.findByIdAndUpdate(
      addressId,
      {
        title,
        name,
        phone,
        address,
        city,
        state,
        pincode,
        isDefault,
        updatedAt: new Date(),
      },
      { new: true },
    )

    res.json({
      success: true,
      message: "Address updated successfully",
      address: updatedAddress,
    })
  } catch (error) {
    console.error("Update address error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to update address",
    })
  }
})

// Delete address
app.delete("/api/addresses/:id", authenticateToken, async (req, res) => {
  try {
    const addressId = req.params.id

    const address = await Address.findOneAndDelete({
      _id: addressId,
      userId: req.user.id,
    })

    if (!address) {
      return res.status(404).json({
        success: false,
        message: "Address not found",
      })
    }

    // If deleted address was default, make another address default
    if (address.isDefault) {
      const firstAddress = await Address.findOne({ userId: req.user.id })
      if (firstAddress) {
        firstAddress.isDefault = true
        await firstAddress.save()
      }
    }

    res.json({
      success: true,
      message: "Address deleted successfully",
    })
  } catch (error) {
    console.error("Delete address error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to delete address",
    })
  }
})

// =============================================================================
// RAZORPAY & PAYMENT APIs - COMMENTED FOR DEVELOPMENT
// =============================================================================

/*
// Create Razorpay order
app.post('/api/create-razorpay-order', authenticateToken, async (req, res) => {
  try {
    const { amount, currency = 'INR' } = req.body;

    if (!amount || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Valid amount is required'
      });
    }

    const options = {
      amount: Math.round(amount), // Amount in paise
      currency,
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1
    };

    const order = await razorpay.orders.create(options);

    res.json({
      success: true,
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      receipt: order.receipt
    });
  } catch (error) {
    console.error('Create Razorpay order error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create payment order'
    });
  }
});

// Verify Razorpay payment
app.post('/api/verify-razorpay-payment', authenticateToken, async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

    const sign = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest("hex");

    if (razorpay_signature === expectedSign) {
      res.json({
        success: true,
        message: 'Payment verified successfully',
        paymentId: razorpay_payment_id,
        orderId: razorpay_order_id
      });
    } else {
      res.status(400).json({
        success: false,
        message: 'Invalid payment signature'
      });
    }
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({
      success: false,
      message: 'Payment verification failed'
    });
  }
});
*/

// =============================================================================
// ORDER MANAGEMENT APIs
// =============================================================================

// Create order
app.post("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { items, address, paymentMethod, paymentId, razorpayOrderId, subtotal, deliveryFee, taxAmount, totalAmount } =
      req.body

    // Validate required fields
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({
        success: false,
        message: "Order items are required",
      })
    }

    if (!address || !address.name || !address.phone || !address.address) {
      return res.status(400).json({
        success: false,
        message: "Delivery address is required",
      })
    }

    if (!paymentMethod || !["cod", "online"].includes(paymentMethod)) {
      return res.status(400).json({
        success: false,
        message: "Valid payment method is required",
      })
    }

    // Generate unique order ID
    const orderId = generateOrderId()

    // Set payment status based on payment method
    let paymentStatus = "pending"
    if (paymentMethod === "cod") {
      paymentStatus = "pending" // COD remains pending until delivery
    } else if (paymentMethod === "online" && paymentId) {
      paymentStatus = "paid"
    }

    // Calculate estimated delivery (7 days from now)
    const estimatedDelivery = new Date()
    estimatedDelivery.setDate(estimatedDelivery.getDate() + 7)

    const order = new Order({
      userId: req.user.id,
      orderId,
      items,
      address,
      paymentMethod,
      paymentStatus,
      paymentId,
      razorpayOrderId,
      subtotal,
      deliveryFee,
      taxAmount,
      totalAmount,
      orderStatus: "confirmed",
      estimatedDelivery,
    })

    await order.save()

    // Clear user's cart after successful order
    try {
      await Cart.deleteOne({ userId: req.user.id })
    } catch (cartError) {
      console.error("Failed to clear cart after order:", cartError)
      // Don't fail the order if cart clearing fails
    }

    // Send order confirmation email
    try {
      const user = await User.findById(req.user.id)
      await sendOrderConfirmationEmail(user, order)
    } catch (emailError) {
      console.error("Failed to send order confirmation email:", emailError)
      // Don't fail the order creation if email fails
    }

    res.status(201).json({
      success: true,
      message: "Order placed successfully!",
      order_id: order.orderId,
      order: {
        id: order._id,
        orderId: order.orderId,
        totalAmount: order.totalAmount,
        paymentStatus: order.paymentStatus,
        orderStatus: order.orderStatus,
        estimatedDelivery: order.estimatedDelivery,
        createdAt: order.createdAt,
      },
    })
  } catch (error) {
    console.error("Create order error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to create order",
    })
  }
})

// Get user orders
app.get("/api/orders", authenticateToken, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query

    const query = { userId: req.user.id }
    if (status) {
      query.orderStatus = status
    }

    const orders = await Order.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)

    const total = await Order.countDocuments(query)

    res.json({
      success: true,
      orders,
      totalPages: Math.ceil(total / limit),
      currentPage: Number.parseInt(page),
      totalOrders: total,
    })
  } catch (error) {
    console.error("Get orders error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch orders",
    })
  }
})

// Get single order
app.get("/api/orders/:orderId", authenticateToken, async (req, res) => {
  try {
    const order = await Order.findOne({
      orderId: req.params.orderId,
      userId: req.user.id,
    })

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      })
    }

    res.json({
      success: true,
      order,
    })
  } catch (error) {
    console.error("Get order error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch order",
    })
  }
})

// Cancel order
app.patch("/api/orders/:orderId/cancel", authenticateToken, async (req, res) => {
  try {
    const { reason } = req.body

    const order = await Order.findOne({
      orderId: req.params.orderId,
      userId: req.user.id,
    })

    if (!order) {
      return res.status(404).json({
        success: false,
        message: "Order not found",
      })
    }

    // Check if order can be cancelled
    if (!["pending", "confirmed"].includes(order.orderStatus)) {
      return res.status(400).json({
        success: false,
        message: "Order cannot be cancelled at this stage",
      })
    }

    order.orderStatus = "cancelled"
    order.cancelledAt = new Date()
    order.cancellationReason = reason || "Cancelled by user"
    order.updatedAt = new Date()

    // If payment was made online, mark for refund
    if (order.paymentMethod === "online" && order.paymentStatus === "paid") {
      order.paymentStatus = "refunded"
    }

    await order.save()

    res.json({
      success: true,
      message: "Order cancelled successfully",
      order: {
        orderId: order.orderId,
        orderStatus: order.orderStatus,
        cancelledAt: order.cancelledAt,
      },
    })
  } catch (error) {
    console.error("Cancel order error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to cancel order",
    })
  }
})

// =============================================================================
// EMAIL FUNCTIONS
// =============================================================================

// Send order confirmation email
async function sendOrderConfirmationEmail(user, order) {
  const itemsList = order.items.map((item) => `<li>${item.name} - Qty: ${item.quantity} - ₹${item.price}</li>`).join("")

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: user.email,
    subject: `Order Confirmation - ${order.orderId}`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
        <h2 style="color: #4CAF50; text-align: center;">Order Confirmed!</h2>
        <p>Hello ${user.name},</p>
        <p>Thank you for your order. Here are the details:</p>
        
        <div style="background-color: #f5f5f5; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <h3>Order Details</h3>
          <p><strong>Order ID:</strong> ${order.orderId}</p>
          <p><strong>Total Amount:</strong> ₹${order.totalAmount}</p>
          <p><strong>Payment Method:</strong> ${order.paymentMethod === "cod" ? "Cash on Delivery" : "Online Payment"}</p>
          <p><strong>Payment Status:</strong> ${order.paymentStatus}</p>
          <p><strong>Estimated Delivery:</strong> ${order.estimatedDelivery.toDateString()}</p>
        </div>

        <div style="background-color: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <h3>Items Ordered</h3>
          <ul>${itemsList}</ul>
        </div>

        <div style="background-color: #f0f8ff; padding: 15px; margin: 20px 0; border-radius: 5px;">
          <h3>Delivery Address</h3>
          <p>${order.address.name}<br>
          ${order.address.phone}<br>
          ${order.address.address}<br>
          ${order.address.city}, ${order.address.state} - ${order.address.pincode}</p>
        </div>

        <p>We'll keep you updated on your order status.</p>
        <p>Thank you for shopping with us!</p>
        
        <p style="margin-top: 30px; font-size: 12px; color: #777; text-align: center;">
          This is an automated email. Please do not reply.
        </p>
      </div>
    `,
  }

  await transporter.sendMail(mailOptions)
}

// =============================================================================
// EXISTING ROUTES (keeping all your existing functionality)
// =============================================================================

// User Info Update API
app.put("/api/user/update-info", authenticateToken, async (req, res) => {
  try {
    const { name, phone } = req.body
    if (!name && !phone) {
      return res.status(400).json({ success: false, message: "Nothing to update" })
    }

    if (phone) {
      const phoneExists = await User.findOne({ phone, _id: { $ne: req.user.id } })
      if (phoneExists) {
        return res.status(400).json({ success: false, message: "Phone number already exists." })
      }
    }

    const user = await User.findById(req.user.id)
    if (!user) return res.status(404).json({ success: false, message: "User not found" })

    if (name) user.name = name
    if (phone) user.phone = phone
    user.updatedAt = new Date()
    await user.save()

    res.json({
      success: true,
      message: "User information updated successfully",
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        userType: user.userType,
      },
    })
  } catch (error) {
    console.error("Update info error:", error)
    res.status(500).json({ success: false, message: "Failed to update user info" })
  }
})

// Register User (With OTP verification)
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, phone, password } = req.body

    const existingUser = await User.findOne({
      $or: [{ email }, { phone }],
    })

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email or phone number.",
      })
    }

    const hashedPassword = await bcrypt.hash(password, 10)

    const user = new User({
      name,
      email,
      phone,
      password: hashedPassword,
      userType: "buyer",
      isVerified: false,
    })

    await user.save()

    const otp = generateOTP()
    const expiresAt = new Date()
    expiresAt.setMinutes(expiresAt.getMinutes() + 15)
    await OTP.deleteMany({ email })
    const otpDoc = new OTP({
      email,
      otp,
      expiresAt,
    })
    await otpDoc.save()

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Signup OTP Verification",
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
          <h2 style="color: #333; text-align: center;">OTP Verification</h2>
          <p>Hello ${name},</p>
          <p>Your OTP for verifying your account is:</p>
          <div style="background-color: #f5f5f5; padding: 15px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0;">
            ${otp}
          </div>
          <p>This OTP will expire in 15 minutes.</p>
          <p>If you did not sign up, please ignore this email.</p>
          <p style="margin-top: 30px; font-size: 12px; color: #777; text-align: center;">
            This is an automated email. Please do not reply.
          </p>
        </div>
      `,
    }
    await transporter.sendMail(mailOptions)

    res.status(201).json({
      success: true,
      message: "Account created! Please verify your email with the OTP sent.",
    })
  } catch (error) {
    console.error("Signup error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred during signup. Please try again.",
    })
  }
})

// Verify Signup OTP
app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body
    if (!email || !otp) {
      return res.status(400).json({
        success: false,
        message: "Email and OTP are required",
      })
    }
    const otpDoc = await OTP.findOne({ email, otp })
    if (!otpDoc) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP",
      })
    }
    if (new Date() > otpDoc.expiresAt) {
      await OTP.deleteOne({ _id: otpDoc._id })
      return res.status(400).json({
        success: false,
        message: "OTP has expired",
      })
    }

    const user = await User.findOne({ email })
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      })
    }
    user.isVerified = true
    user.updatedAt = new Date()
    await user.save()
    await OTP.deleteOne({ _id: otpDoc._id })

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "7d",
    })
    const userData = {
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      userType: user.userType,
      profileImage: user.profileImage,
      createdAt: user.createdAt,
      isVerified: user.isVerified,
    }

    res.json({
      success: true,
      message: "Email verified successfully!",
      user: userData,
      token,
    })
  } catch (error) {
    console.error("Verify signup otp error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred while verifying OTP",
    })
  }
})

// Login User
app.post("/api/auth/login", async (req, res) => {
  try {
    const { emailOrPhone, password } = req.body
    const user = await User.findOne({
      $or: [{ email: emailOrPhone }, { phone: emailOrPhone }],
    })
    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials. Please check your email/phone and password.",
      })
    }
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials. Please check your email/phone and password.",
      })
    }
    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET || "your-secret-key", {
      expiresIn: "7d",
    })
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
      createdAt: user.createdAt,
    }
    res.json({
      success: true,
      message: "Login successful!",
      user: userData,
      token,
    })
  } catch (error) {
    console.error("Login error:", error)
    res.status(500).json({
      success: false,
      message: "An error occurred during login. Please try again.",
    })
  }
})

// Get all items (products)
app.get("/api/items", async (req, res) => {
  try {
    const { category, search, page = 1, limit = 20 } = req.query

    const query = { isAvailable: true }

    if (category) {
      query.category = { $regex: category, $options: "i" }
    }

    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
        { category: { $regex: search, $options: "i" } },
      ]
    }

    const items = await Item.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit)

    const total = await Item.countDocuments(query)

    res.json({
      success: true,
      items,
      totalPages: Math.ceil(total / limit),
      currentPage: Number.parseInt(page),
      totalItems: total,
    })
  } catch (error) {
    console.error("Get items error:", error)
    res.status(500).json({
      success: false,
      message: "Failed to fetch items",
    })
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`)
  console.log("\n=== ENVIRONMENT VARIABLES NEEDED ===")
  console.log("JWT_SECRET=your_jwt_secret")
  console.log("EMAIL_USER=your_email@gmail.com")
  console.log("EMAIL_PASSWORD=your_app_password")
  console.log("MONGODB_URI=your_mongodb_connection_string")
  console.log("// RAZORPAY_KEY_ID=your_razorpay_key_id (commented for development)")
  console.log("// RAZORPAY_KEY_SECRET=your_razorpay_key_secret (commented for development)")
  console.log("=====================================\n")
})

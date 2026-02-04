const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios');
const cron = require('node-cron');
const FormData = require('form-data');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root Route
app.get('/', (req, res) => {
    res.send('ISP Backend is Running!');
});

// Database Connection
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.log('MongoDB Connection Error:', err));

// --- Schemas & Models ---

// 1. User (Staff/Admin)
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true }, // Phone or username
    password: { type: String, required: true },
    role: {
        type: String,
        enum: ['admin', 'billing_manager', 'collector', 'support_staff'],
        default: 'admin'
    },
    permissions: [String], // Specific permissions if needed
    joinedDate: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// 2. Zone/Area
const zoneSchema = new mongoose.Schema({
    name: { type: String, required: true },
    type: { type: String, enum: ['zone', 'sub-zone', 'area'], required: true },
    parentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Zone', default: null }, // For hierarchy
    description: String
});
const Zone = mongoose.model('Zone', zoneSchema);

// 2.5 Package
const packageSchema = new mongoose.Schema({
    name: { type: String, required: true },
    price: { type: Number, required: true },
    speed: { type: String, required: true },
    type: { type: String, default: 'Residential' }, // Residential, Corporate, etc.
    color: { type: String, default: 'blue' }, // For UI styling
    description: String,
    isActive: { type: Boolean, default: true }
});
const Package = mongoose.model('Package', packageSchema);

// 3. Customer
const customerSchema = new mongoose.Schema({
    // Basic Info
    name: { type: String, required: true },
    mobile: { type: String, required: true },
    address: { type: String },
    nid: { type: String },

    // Login Info
    username: { type: String }, // Can be mobile or custom
    password: { type: String },

    // Package Info
    packageName: { type: String, required: true },
    packageSpeed: { type: String }, // e.g., "10 Mbps"
    packagePrice: { type: Number, required: true },

    // Connection Info
    status: { type: String, enum: ['active', 'inactive', 'suspended'], default: 'active' },
    connectionDate: { type: Date },
    billingDate: { type: Date }, // e.g., 5th of every month

    // Location
    area: String, // Changed to free text string as per user request
    areaId: { type: mongoose.Schema.Types.ObjectId, ref: 'Zone' }, // Keeping this for backward compatibility if any, or we can remove it. Let's keep it but optional.

    // Billing State
    currentDue: { type: Number, default: 0 },

    // Tech
    ipAddress: String,
    macAddress: String,

    createdAt: { type: Date, default: Date.now }
});
const Customer = mongoose.model('Customer', customerSchema);

// 4. Bill/Invoice
const billSchema = new mongoose.Schema({
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer', required: true },
    month: { type: String, required: true }, // e.g., "January 2026"
    year: { type: Number, required: true },
    amount: { type: Number, required: true },
    paidAmount: { type: Number, default: 0 },
    discount: { type: Number, default: 0 },
    status: { type: String, enum: ['unpaid', 'paid', 'partial'], default: 'unpaid' },
    dueDate: { type: Date },
    generatedAt: { type: Date, default: Date.now },
    paidAt: Date,
    collectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Who collected the bill
});
const Bill = mongoose.model('Bill', billSchema);

// 5. Inventory/Asset
const inventorySchema = new mongoose.Schema({
    name: { type: String, required: true },
    category: { type: String },
    quantity: { type: Number, default: 0 },
    unit: { type: String }, // pcs, meter, etc.
    purchasePrice: { type: Number },
    description: String,
    imageUrl: String,
    updatedAt: { type: Date, default: Date.now }
});
const Inventory = mongoose.model('Inventory', inventorySchema);

// 6. Transaction (Creating a separate log for payments)
const transactionSchema = new mongoose.Schema({
    customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Customer' },
    billId: { type: mongoose.Schema.Types.ObjectId, ref: 'Bill' },
    amount: { type: Number, required: true },
    type: { type: String, enum: ['bill_payment', 'opening_balance', 'adjustment'], default: 'bill_payment' },
    collectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    date: { type: Date, default: Date.now },
    paymentMethod: { type: String, default: 'cash' },
    remarks: String,
    paidBills: [{
        billId: { type: mongoose.Schema.Types.ObjectId, ref: 'Bill' },
        amount: { type: Number }
    }] // Track which bills were covered
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// --- Helpers & Middleware ---

// Image Upload (Multer Memory Storage)
const upload = multer({ storage: multer.memoryStorage() });

const uploadToImageBB = async (buffer) => {
    try {
        const formData = new FormData();
        formData.append('image', buffer.toString('base64'));

        const response = await axios.post(`https://api.imgbb.com/1/upload?key=${process.env.IMAGEBB_API_KEY}`, formData, {
            headers: formData.getHeaders()
        });
        return response.data.data.url;
    } catch (error) {
        console.error('ImageBB Upload Error:', error.message);
        return null;
    }
};

// Auth Middleware
const authenticate = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (ex) {
        res.status(401).json({ message: 'Invalid token.' });
    }
};

const authorize = (roles = []) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Access denied.' });
        }
        next();
    };
};

// --- Routes ---

// 1. Auth Routes
app.post('/api/auth/register', async (req, res) => {
    // Only admin usually should register staff, but for setup we allow open or restrict
    // Taking simplified approach for now
    try {
        const { name, username, password, role } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, username, password: hashedPassword, role });
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) return res.status(400).json({ message: 'Invalid credentials' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.json({ token, user: { id: user._id, name: user.name, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/users', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const users = await User.find().select('-password');
        res.json(users);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 2. Customer Routes
app.get('/api/customers', authenticate, async (req, res) => {
    try {
        const customers = await Customer.find().populate('areaId');
        res.json(customers);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



app.post('/api/customers', authenticate, async (req, res) => {
    try {
        const { previousDueDetails, ...customerData } = req.body;
        const customer = new Customer(customerData);

        // Calculate initial due from previous details
        let initialDue = 0;
        if (previousDueDetails && Array.isArray(previousDueDetails)) {
            for (const detail of previousDueDetails) {
                const amount = Number(detail.amount);
                if (detail.month && detail.year && amount > 0) {
                    initialDue += amount;
                    // Create a dummy/opening bill for this history
                    const bill = new Bill({
                        customerId: customer._id,
                        month: detail.month,
                        year: Number(detail.year),
                        amount: amount,
                        status: 'unpaid',
                        dueDate: new Date(), // Already due
                        generatedAt: new Date(Number(detail.year), 0, 1) // Rough date
                    });
                    await bill.save();
                }
            }
        }

        customer.currentDue = (customer.currentDue || 0) + initialDue;
        await customer.save();
        res.status(201).json(customer);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/customers/:id', authenticate, async (req, res) => {
    try {
        const { previousDueDetails, ...updateData } = req.body;

        // 1. Handle Previous Due / Opening Balance additions
        let additionalDue = 0;
        if (previousDueDetails && Array.isArray(previousDueDetails)) {
            for (const detail of previousDueDetails) {
                const amount = Number(detail.amount);
                // Validation: amount > 0 and date info present
                if (detail.month && detail.year && amount > 0) {

                    // Check if bill already exists to prevent double-counting
                    const existingBill = await Bill.findOne({
                        customerId: req.params.id,
                        month: detail.month,
                        year: Number(detail.year)
                    });

                    if (!existingBill) {
                        const bill = new Bill({
                            customerId: req.params.id,
                            month: detail.month,
                            year: Number(detail.year),
                            amount: amount,
                            status: 'unpaid',
                            dueDate: new Date(),
                            generatedAt: new Date(Number(detail.year), 0, 1)
                        });
                        await bill.save();
                        additionalDue += amount;
                    }
                }
            }
        }

        // 2. Update Customer
        // If we added new bills, we must increment currentDue
        // We also want to apply any other updates from req.body
        const customer = await Customer.findByIdAndUpdate(
            req.params.id,
            {
                ...updateData,
                $inc: { currentDue: additionalDue }
            },
            { new: true }
        );

        res.json(customer);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/customers/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        await Customer.findByIdAndDelete(req.params.id);
        res.json({ message: 'Customer deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 3. Billing Routes
app.post('/api/bills/generate-monthly', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const { month, year } = req.body; // e.g., "February", 2026
        const activeCustomers = await Customer.find({ status: 'active' });

        const bills = [];
        for (const customer of activeCustomers) {
            // Check if bill already exists for this month/year
            const existing = await Bill.findOne({
                customerId: customer._id,
                month: month,
                year: year
            });

            if (!existing) {
                // Determine due date (e.g., 10th of month or customer specific)
                const dueDate = new Date(year, new Date().getMonth() + 1, 10); // Simple default

                const bill = new Bill({
                    customerId: customer._id,
                    month,
                    year,
                    amount: customer.packagePrice,
                    dueDate,
                    status: 'unpaid'
                });
                bills.push(bill);
            }
        }

        if (bills.length > 0) {
            await Bill.insertMany(bills);

            // Update customer due amounts
            for (const bill of bills) {
                await Customer.findByIdAndUpdate(bill.customerId, {
                    $inc: { currentDue: bill.amount }
                });
            }
        }

        res.json({ message: `Generated ${bills.length} bills for ${month} ${year}` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/bills', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const { customerId, month, year, amount, dueDate } = req.body;

        const bill = new Bill({
            customerId,
            month,
            year,
            amount,
            dueDate: dueDate || new Date(),
            status: 'unpaid'
        });
        await bill.save();

        // Update customer due
        await Customer.findByIdAndUpdate(customerId, {
            $inc: { currentDue: Number(amount) }
        });

        res.status(201).json(bill);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/bills/:id', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const { amount, status, month, year } = req.body;
        const bill = await Bill.findById(req.params.id);
        if (!bill) return res.status(404).json({ message: 'Bill not found' });

        // Calculate difference in amount to adjust customer due
        const amountDiff = Number(amount) - bill.amount;

        // Update fields
        bill.amount = Number(amount);
        if (month) bill.month = month;
        if (year) bill.year = year;

        // Auto-update status if paid amount covers new total? 
        // Or trust the status passed, or re-evaluate.
        // If status passed, use it, otherwise re-calc based on paidAmount
        if (status) {
            bill.status = status;
        } else {
            if (bill.paidAmount >= bill.amount) bill.status = 'paid';
            else if (bill.paidAmount > 0) bill.status = 'partial';
            else bill.status = 'unpaid';
        }

        await bill.save();

        // Adjust customer due if amount changed
        if (amountDiff !== 0) {
            await Customer.findByIdAndUpdate(bill.customerId, {
                $inc: { currentDue: amountDiff }
            });
        }

        res.json(bill);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/bills', authenticate, async (req, res) => {
    try {
        const { customerId, status, month, year, mobile } = req.query;
        let query = {};
        if (customerId) query.customerId = customerId;
        if (status) query.status = status;
        if (month) query.month = month;
        if (year) query.year = year;

        if (mobile) {
            const customers = await Customer.find({ mobile: { $regex: mobile, $options: 'i' } }).select('_id');
            const customerIds = customers.map(c => c._id);
            if (!customerId) {
                query.customerId = { $in: customerIds };
            }
        }

        const bills = await Bill.find(query)
            .populate({
                path: 'customerId',
                select: 'name mobile address packageName currentDue areaId',
                populate: { path: 'areaId', select: 'name' }
            })
            .populate('collectedBy', 'name')
            .sort({ year: -1, month: -1 }); // Sort by latest
        res.json(bills);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/bills/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const bill = await Bill.findById(req.params.id);
        if (!bill) return res.status(404).json({ message: 'Bill not found' });

        // Decrease customer due before deleting
        // If bill was NOT paid or PARTIAL, we reduce the due by remaining amount? 
        // Logic: currentDue tracks total owed. If we delete a bill of 500, we should remove 500 from due.
        // But if they paid 200, due was already reduced by 200?
        // Wait, when bill is created, due += amount.
        // When paid, due -= amount.
        // So if we delete the bill, we should reverse the creation effect: due -= (bill.amount - bill.paidAmount) ???
        // Or simply remove the bill's existence. 
        // If I delete a bill of 1000. Customer has 1000 due. I delete it. Due should differ.
        // But what if they partly paid?
        // Payment logic: Customer.due -= payment. 
        // Bill creation logic: Customer.due += bill amount.
        // So if delete bill: Customer.due -= bill amount.
        // AND if there were payments associated with this bill, those payments are technically "floating" or should be reversed?
        // For simplicity: We remove the FULL bill amount from customer due. 
        // The payments made are separate transactions. If we delete a bill, the payments technically made 'advance' or 'credit'? 
        // Let's assume deletion is for "Double added" bills (unpaid usually).
        // If unpaid: due -= amount.
        // If paid: due -= amount. (Because when paid, due was reduced. So net effect on Due was 0. If we delete bill, we are saying "this charge never happened". But they paid. So they should have credit.)
        // Correct logic: Customer.currentDue -= bill.amount;

        await Customer.findByIdAndUpdate(bill.customerId, {
            $inc: { currentDue: -bill.amount }
        });

        // Delete the bill
        await Bill.findByIdAndDelete(req.params.id);

        // Also cleanup transactions? Optional. For now let's keep it simple.

        res.json({ message: 'Bill deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/bills/pay', authenticate, async (req, res) => {
    try {
        // Can pay specific bill or just add amount to customer account
        const { billId, amount, customerId } = req.body;

        // Strategy: If billId provided, pay that bill. If just customerId, adjust due.
        // User requirements: "Manual bill edit option" -> This covers payment.

        let transaction;

        if (billId) {
            const bill = await Bill.findById(billId);
            if (!bill) return res.status(404).json({ message: 'Bill not found' });

            bill.paidAmount += Number(amount);
            if (bill.paidAmount >= bill.amount) bill.status = 'paid';
            else bill.status = 'partial';
            bill.paidAt = new Date(); // Updates last payment time
            bill.collectedBy = req.user.id;
            await bill.save();

            // Reduce customer due
            await Customer.findByIdAndUpdate(bill.customerId, { $inc: { currentDue: -Number(amount) } });

            transaction = new Transaction({
                customerId: bill.customerId,
                billId: bill._id,
                amount: Number(amount),
                collectedBy: req.user.id,
                type: 'bill_payment'
            });
            await transaction.save();

        } else if (customerId) {
            // General payment on account
            // 1. Reduce Customer Due
            await Customer.findByIdAndUpdate(customerId, { $inc: { currentDue: -Number(amount) } });

            // 2. Auto-allocate payment to unpaid bills (Oldest first or by month?)
            // Strategy: Find unpaid bills, pay them off one by one starting from oldest.
            let remainingPayment = Number(amount);

            // Find bills that are NOT fully paid
            const unpaidBills = await Bill.find({
                customerId: customerId,
                status: { $ne: 'paid' }
            }).sort({ year: 1, month: 1 }); // Sort by time (approx, assuming month names are chronologically handled or just rely on _id/createdAt? _id is better but year/month is explicit)
            // Note: Month string sorting is tricky ("January", "February"). 
            // Better to sort by _id which implies time, or createdAt.
            // Let's rely on _id (creation time) for simplicity.
            // But we might have manual entries.
            // Let's assume standard creation order is fine.

            // Refetch with ID sort
            const billsToPay = await Bill.find({
                customerId: customerId,
                status: { $ne: 'paid' }
            }).sort({ _id: 1 });

            let paidBillsLog = [];

            for (const bill of billsToPay) {
                if (remainingPayment <= 0) break;

                const billDue = bill.amount - (bill.paidAmount || 0);
                const paymentForThisBill = Math.min(remainingPayment, billDue);

                bill.paidAmount = (bill.paidAmount || 0) + paymentForThisBill;
                if (bill.paidAmount >= bill.amount) {
                    bill.status = 'paid';
                } else {
                    bill.status = 'partial';
                }
                bill.paidAt = new Date();
                bill.collectedBy = req.user.id;

                await bill.save();
                remainingPayment -= paymentForThisBill;

                paidBillsLog.push({ billId: bill._id, amount: paymentForThisBill });
            }

            // 3. Record Transaction
            transaction = new Transaction({
                customerId: customerId,
                amount: Number(amount),
                collectedBy: req.user.id,
                type: 'bill_payment',
                paymentMethod: req.body.paymentMethod || 'cash',
                paidBills: paidBillsLog
            });
            await transaction.save();
        }

        // Mock SMS Notification (In real app, integrate SMS API here)
        // sendSMS(customerMobile, `Payment of ${amount} received. Thanks.`);

        res.json({ message: 'Payment recorded successfully', transaction });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/transactions/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) return res.status(404).json({ message: 'Transaction not found' });

        // Reverse effects
        // 1. Increase Customer Due
        await Customer.findByIdAndUpdate(transaction.customerId, {
            $inc: { currentDue: transaction.amount }
        });

        // 2. Revert Bill Statuses using paidBills log
        if (transaction.paidBills && transaction.paidBills.length > 0) {
            for (const pb of transaction.paidBills) {
                const bill = await Bill.findById(pb.billId);
                if (bill) {
                    bill.paidAmount = Math.max(0, (bill.paidAmount || 0) - pb.amount);
                    // Reset status
                    if (bill.paidAmount === 0) bill.status = 'unpaid';
                    else if (bill.paidAmount < bill.amount) bill.status = 'partial';
                    // If specifically fully paid before, collectedBy might need reset if paidAmount is 0?
                    // Let's leave collectedBy as last toucher or maybe clear it if unpaid
                    if (bill.status === 'unpaid') {
                        bill.paidAt = null;
                        bill.collectedBy = null;
                    }
                    await bill.save();
                }
            }
        } else if (transaction.billId) {
            // Backward compatibility or direct bill pay
            const bill = await Bill.findById(transaction.billId);
            if (bill) {
                bill.paidAmount -= transaction.amount;
                if (bill.paidAmount <= 0) {
                    bill.status = 'unpaid';
                    bill.paidAt = null;
                } else {
                    bill.status = 'partial';
                }
                await bill.save();
            }
        }

        await Transaction.findByIdAndDelete(req.params.id);
        res.json({ message: 'Transaction deleted and reverted successfully' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/transactions/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const { amount, paymentMethod, date } = req.body;
        const transaction = await Transaction.findById(req.params.id);
        if (!transaction) return res.status(404).json({ message: 'Transaction not found' });

        // 1. Revert Old Transaction Effects
        // Increase Customer Due
        await Customer.findByIdAndUpdate(transaction.customerId, {
            $inc: { currentDue: transaction.amount }
        });

        // Revert Bill Statuses
        if (transaction.paidBills && transaction.paidBills.length > 0) {
            for (const pb of transaction.paidBills) {
                const bill = await Bill.findById(pb.billId);
                if (bill) {
                    bill.paidAmount = Math.max(0, (bill.paidAmount || 0) - pb.amount);
                    if (bill.paidAmount === 0) {
                        bill.status = 'unpaid';
                        bill.paidAt = null;
                        bill.collectedBy = null;
                    } else if (bill.paidAmount < bill.amount) {
                        bill.status = 'partial';
                    }
                    await bill.save();
                }
            }
        }

        // 2. Update Transaction Data
        transaction.amount = Number(amount);
        transaction.paymentMethod = paymentMethod || transaction.paymentMethod;
        transaction.date = date || transaction.date;
        // Clear old logs to be regenerated
        transaction.paidBills = [];

        // 3. Apply New Transaction Effects
        // Decrease Customer Due
        await Customer.findByIdAndUpdate(transaction.customerId, {
            $inc: { currentDue: -Number(amount) }
        });

        // Auto-allocate to bills (Fresh allocation)
        let remainingPayment = Number(amount);
        const billsToPay = await Bill.find({
            customerId: transaction.customerId,
            status: { $ne: 'paid' }
        }).sort({ _id: 1 });

        let newPaidBillsLog = [];

        for (const bill of billsToPay) {
            if (remainingPayment <= 0) break;

            const billDue = bill.amount - (bill.paidAmount || 0);
            const paymentForThisBill = Math.min(remainingPayment, billDue);

            bill.paidAmount = (bill.paidAmount || 0) + paymentForThisBill;
            if (bill.paidAmount >= bill.amount) {
                bill.status = 'paid';
            } else {
                bill.status = 'partial';
            }
            bill.paidAt = new Date();
            // Preserve original collector if just editing amount, or update? 
            // If admin edits, admin is handling it? Let's keep original collector or update if significant.
            // Let's keep logical continuity: editing fixes a record, doesn't change collector usually.
            // But we can update collectedBy to the editor if we want. Let's keep it simple.

            await bill.save();
            remainingPayment -= paymentForThisBill;

            newPaidBillsLog.push({ billId: bill._id, amount: paymentForThisBill });
        }

        transaction.paidBills = newPaidBillsLog;
        await transaction.save();

        res.json({ message: 'Transaction updated successfully', transaction });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/transactions', authenticate, async (req, res) => {
    try {
        // Fetch recent transactions, populated with names
        const transactions = await Transaction.find()
            .sort({ date: -1 })
            .limit(50)
            .populate('customerId', 'name mobile')
            .populate('collectedBy', 'name')
            .populate({
                path: 'paidBills.billId',
                select: 'month year amount'
            });

        res.json(transactions);

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/seed-zones', async (req, res) => {
    try {
        const zonesData = [
            {
                name: "Nalghar",
                subZones: [
                    "Nalghar Bazar", "Nalghar CP", "Nalghar HB", "Nalghar Mure Bare",
                    "Nalghar Possim Para", "Nalghar Purbo Para", "Nalghar Noya Bare",
                    "Nalghar Bazar Purbodig", "Nalghar Borobangna"
                ]
            },
            {
                name: "Jospur",
                subZones: [
                    "Jospur Narayounpur Road", "Jospur Mollah B", "Jospur Miazi B",
                    "Jospur Joinal Member B", "Jospur Hazi Abdur Rashid R Pasa", "Jospur Dokhin Matha"
                ]
            },
            {
                name: "Gopalnogor",
                subZones: [
                    "Gopalnogor Mure B", "Gopalnogor Abdul Master B", "Gopalnogor Khaish Road",
                    "Gopalnogor Lainga Market", "GOPALNOGOR Bazlu Member House",
                    "Gopalnogor Mollah B", "Gopalnogor Jahangir Vaier B"
                ]
            },
            { name: "Ducure", subZones: [] },
            { name: "Bangalmure", subZones: [] },
            { name: "Tarapuskorone", subZones: [] },
            { name: "Dokhin Gopalnogor", subZones: [] },
        ];

        await Zone.deleteMany({});

        const created = [];
        for (const z of zonesData) {
            const zone = await new Zone({ name: z.name, type: 'zone' }).save();
            created.push(zone);
            if (z.subZones) {
                for (const sub of z.subZones) {
                    await new Zone({ name: sub, type: 'sub-zone', parentId: zone._id }).save();
                }
            }
        }
        res.json({ message: 'Zones seeded successfully', data: created });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Zone Management Routes
app.get('/api/zones', authenticate, async (req, res) => {
    try {
        // Return all zones
        const zones = await Zone.find();
        res.json(zones);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/zones', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const { name, type, parentId } = req.body;
        const zone = new Zone({ name, type, parentId });
        await zone.save();
        res.status(201).json(zone);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/zones/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const zone = await Zone.findById(req.params.id);
        if (!zone) return res.status(404).json({ message: 'Zone not found' });

        // Delete children recursively? Or just one level?
        // Simple 1-level cascade for now (sub-zones of a zone)
        // If it's a zone, delete all sub-zones and areas that have this parentId

        // Find all children
        const children = await Zone.find({ parentId: zone._id });
        const childIds = children.map(c => c._id);

        // Delete grandchildren (if any, assuming 3 levels: Zone -> Sub -> Area)
        await Zone.deleteMany({ parentId: { $in: childIds } });

        // Delete children
        await Zone.deleteMany({ parentId: zone._id });

        // Delete self
        await Zone.findByIdAndDelete(req.params.id);

        res.json({ message: 'Zone and children deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. Dashboard Stats
app.get('/api/dashboard', authenticate, async (req, res) => {
    try {
        const { month, year } = req.query; // Optional filters for "Running Month" specific stats
        const now = new Date();
        const currentMonthName = month || now.toLocaleString('default', { month: 'long' });
        const currentYear = year ? Number(year) : now.getFullYear();

        // 1. Total Bill Generated (Filtered by Month/Year)
        const totalBillResult = await Bill.aggregate([
            {
                $match: {
                    month: currentMonthName,
                    year: currentYear
                }
            },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);
        const totalBillGenerated = totalBillResult[0]?.total || 0;

        // 2. Total Monthly Collection (For specific month)
        // Need to filter transactions by date range for that month
        const startOfMonth = new Date(currentYear, new Date(`${currentMonthName} 1, 2000`).getMonth(), 1);
        const endOfMonth = new Date(currentYear, new Date(`${currentMonthName} 1, 2000`).getMonth() + 1, 0, 23, 59, 59);

        const monthlyCollectionResult = await Transaction.aggregate([
            {
                $match: {
                    type: 'bill_payment',
                    date: { $gte: startOfMonth, $lte: endOfMonth }
                }
            },
            { $group: { _id: null, total: { $sum: "$amount" } } }
        ]);
        const totalMonthlyCollection = monthlyCollectionResult[0]?.total || 0;

        // 3. Total Due (Overall Lifetime)
        // This remains overall because "Total Due" implies current outstanding balance of the company
        const totalDueResult = await Customer.aggregate([
            { $group: { _id: null, total: { $sum: "$currentDue" } } }
        ]);
        const totalDue = totalDueResult[0]?.total || 0;

        // 4. Running Month Due (Unpaid/Partial amount for bills of this month)
        const runningMonthDueResult = await Bill.aggregate([
            {
                $match: {
                    month: currentMonthName,
                    year: currentYear
                }
            },
            {
                $group: {
                    _id: null,
                    totalAmount: { $sum: "$amount" },
                    totalPaid: { $sum: "$paidAmount" } // paidAmount is tracked on bill
                }
            }
        ]);
        const stats = runningMonthDueResult[0] || { totalAmount: 0, totalPaid: 0 };
        const runningMonthDue = stats.totalAmount - stats.totalPaid;


        // 5. Monthly Income Chart Data (For Selected Year)
        const monthlyIncomeChart = await Transaction.aggregate([
            {
                $match: {
                    type: 'bill_payment',
                    $expr: { $eq: [{ $year: "$date" }, currentYear] }
                }
            },
            {
                $group: {
                    _id: { $dateToString: { format: "%Y-%m", date: "$date" } },
                    total: { $sum: "$amount" }
                }
            },
            { $sort: { "_id": 1 } }
        ]);

        // 6. Customer Zone Chart
        // Group customers by area (free text or ID)
        const customerZoneChart = await Customer.aggregate([
            {
                $group: {
                    _id: "$area", // Group by area name
                    count: { $sum: 1 }
                }
            },
            { $match: { _id: { $ne: null } } } // Exclude nulls
        ]);


        res.json({
            totalBillGenerated,
            totalMonthlyCollection,
            totalDue,
            runningMonthDue,
            monthlyIncomeChart,
            customerZoneChart,
            currentMonth: currentMonthName,
            currentYear
        });

    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 4. Zone Management
app.get('/api/zones', authenticate, async (req, res) => {
    try {
        const zones = await Zone.find().populate('parentId');
        res.json(zones);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/zones', authenticate, authorize(['admin']), async (req, res) => {
    try {
        const zone = new Zone(req.body);
        await zone.save();
        res.json(zone);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 5. Inventory Management
app.get('/api/inventory', authenticate, async (req, res) => {
    try {
        const items = await Inventory.find();
        res.json(items);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory', authenticate, upload.single('image'), async (req, res) => {
    try {
        let imageUrl = '';
        if (req.file) {
            imageUrl = await uploadToImageBB(req.file.buffer);
        } else if (req.body.imageUrl) {
            imageUrl = req.body.imageUrl;
        }

        const item = new Inventory({
            ...req.body,
            imageUrl
        });
        await item.save();
        res.json(item);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Dashboard / Reports
app.get('/api/dashboard/stats', authenticate, async (req, res) => {
    try {
        const currentMonth = new Date().getMonth(); // 0-11
        const currentYear = new Date().getFullYear();

        // Month string matcher (Simple assumption, in prod use date objects strictly)
        // We stored month as string in BillSchema, let's match roughly or rely on frontend to pass specific filter
        // Better: Use aggregation on creation date or specific query

        const startOfMonth = new Date(currentYear, currentMonth, 1);
        const endOfMonth = new Date(currentYear, currentMonth + 1, 0);

        // 1. Total Bill Generated This Month
        // Finding bills created in this date range
        const totalBills = await Bill.aggregate([
            { $match: { generatedAt: { $gte: startOfMonth, $lte: endOfMonth } } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        // 2. Total Collection This Month (From Transactions)
        const totalCollection = await Transaction.aggregate([
            { $match: { date: { $gte: startOfMonth, $lte: endOfMonth }, type: 'bill_payment' } },
            { $group: { _id: null, total: { $sum: '$amount' } } }
        ]);

        // 3. Total Due (Overall or This Month)
        // Overall due from Customers table
        const totalDueAggregate = await Customer.aggregate([
            { $match: { status: 'active' } },
            { $group: { _id: null, total: { $sum: '$currentDue' } } }
        ]);

        // 4. Counts
        const activeCustomers = await Customer.countDocuments({ status: 'active' });
        const inactiveCustomers = await Customer.countDocuments({ status: 'inactive' });

        res.json({
            totalBillGenerated: totalBills[0]?.total || 0,
            thisMonthCollection: totalCollection[0]?.total || 0,
            totalDueRaw: totalDueAggregate[0]?.total || 0,
            activeCustomers,
            inactiveCustomers
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 7. General Upload (for frontend convenience)
// 5. Package Management routes
app.get('/api/packages', authenticate, async (req, res) => {
    try {
        const packages = await Package.find(); // Return all so we can manage all
        res.json(packages);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/packages', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const pkg = new Package(req.body);
        await pkg.save();
        res.status(201).json(pkg);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/packages/:id', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const pkg = await Package.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.json(pkg);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/packages/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        await Package.findByIdAndDelete(req.params.id);
        res.json({ message: 'Package deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/upload', authenticate, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
        const url = await uploadToImageBB(req.file.buffer);
        res.json({ url });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// 6. Inventory Management Routes
app.get('/api/inventory', authenticate, async (req, res) => {
    try {
        const items = await Inventory.find().sort({ updatedAt: -1 });
        res.json(items);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/inventory', authenticate, authorize(['admin', 'billing_manager']), upload.single('image'), async (req, res) => {
    try {
        const { name, quantity, purchasePrice, description, category, unit } = req.body;
        let imageUrl = '';

        if (req.file) {
            imageUrl = await uploadToImageBB(req.file.buffer);
        }

        const item = new Inventory({
            name,
            quantity: Number(quantity),
            purchasePrice: Number(purchasePrice),
            description,
            category,
            unit,
            imageUrl
        });
        await item.save();
        res.status(201).json(item);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Route for selling/using inventory items
app.post('/api/inventory-sell/:id', authenticate, authorize(['admin', 'billing_manager']), async (req, res) => {
    try {
        const { quantity, reason } = req.body;
        const sellQty = Number(quantity);

        const item = await Inventory.findById(req.params.id);
        if (!item) return res.status(404).json({ message: 'Item not found' });

        if (item.quantity < sellQty) {
            return res.status(400).json({ message: 'Not enough stock available' });
        }

        item.quantity -= sellQty;
        await item.save();

        res.json({ message: 'Stock updated', item });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/inventory/:id', authenticate, authorize(['admin']), async (req, res) => {
    try {
        await Inventory.findByIdAndDelete(req.params.id);
        res.json({ message: 'Item deleted' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Automations (Cron) ---

// Auto Generate Bills on 1st of every month at 2 AM
cron.schedule('0 2 1 * *', async () => {
    console.log('Running Auto Bill Generation...');
    // Simplify: Call the logic used in the route
    // Note: Re-implement logic here to avoid request mock complexity
    try {
        const date = new Date();
        const monthNames = ["January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December"
        ];
        const month = monthNames[date.getMonth()];
        const year = date.getFullYear();

        const activeCustomers = await Customer.find({ status: 'active' });
        const bills = [];

        for (const customer of activeCustomers) {
            const existing = await Bill.findOne({ customerId: customer._id, month, year });
            if (!existing) {
                const dueDate = new Date(year, date.getMonth() + 1, 10);
                const bill = new Bill({
                    customerId: customer._id,
                    month,
                    year,
                    amount: customer.packagePrice,
                    dueDate,
                    status: 'unpaid'
                });
                bills.push(bill);
            }
        }

        if (bills.length > 0) {
            await Bill.insertMany(bills);
            for (const bill of bills) {
                await Customer.findByIdAndUpdate(bill.customerId, { $inc: { currentDue: bill.amount } });
            }
        }
        console.log(`Auto-generated ${bills.length} bills.`);
    } catch (err) {
        console.error('Auto Bill Gen Failed:', err);
    }
});

// Start Server
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

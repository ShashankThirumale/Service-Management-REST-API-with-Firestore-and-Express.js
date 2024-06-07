const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const bcrypt = require('bcrypt'); // For password hashing
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
admin.initializeApp({
  credential: admin.credential.cert('path/to/serviceAccountKey.json')
});

// Secret key for JWT
const secretKey = process.env.JWT_SECRET_KEY;

// Authentication middleware
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(' ')[1];
    try {
      const decodedToken = jwt.verify(token, secretKey);
      req.user = decodedToken;
      next();
    } catch (error) {
      res.status(401).json({ success: false, message: 'Invalid token' });
    }
  } else {
    res.status(401).json({ success: false, message: 'Authorization token required' });
  }
};

// --- SERVICE PROVIDER ENDPOINTS ---

// Register a new service provider
app.post('/api/serviceProviders/register', async (req, res) => {
  const { email, password, companyName } = req.body;
  try {
    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await admin.auth().createUser({
      email,
      password: hashedPassword,
    });
    await admin.firestore().collection('serviceProviders').doc(user.uid).set({
      email,
      password: hashedPassword,
      companyName,
    });
    res.json({ success: true, message: 'Service provider registered successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error registering service provider', error });
  }
});

// Service provider login
app.post('/api/serviceProviders/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await admin.auth().getUserByEmail(email);
    if (user) {
      // Compare password with hashed password in Firestore
      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (isPasswordValid) {
        // Generate JWT token
        const token = jwt.sign({ uid: user.uid }, secretKey, { expiresIn: '1h' });
        res.json({ success: true, message: 'Login successful!', token });
      } else {
        res.status(401).json({ success: false, message: 'Incorrect password' });
      }
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error logging in', error });
  }
});

// Create a new service
app.post('/api/serviceProviders/services', authenticate, async (req, res) => {
  const { name, description, price } = req.body;
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    const serviceDoc = await admin.firestore().collection('services').add({
      name,
      description,
      price,
      providerId,
    });
    // Update service provider's services array
    await admin.firestore().collection('serviceProviders').doc(providerId).update({
      services: admin.firestore.FieldValue.arrayUnion(serviceDoc.id)
    });
    res.json({ success: true, message: 'Service created successfully!', serviceId: serviceDoc.id });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error creating service', error });
  }
});

// Edit an existing service
app.put('/api/serviceProviders/services/:serviceId', authenticate, async (req, res) => {
  const { serviceId } = req.params;
  const { name, description, price } = req.body;
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    await admin.firestore().collection('services').doc(serviceId).update({
      name,
      description,
      price,
    });
    res.json({ success: true, message: 'Service updated successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating service', error });
  }
});

// Delete a service
app.delete('/api/serviceProviders/services/:serviceId', authenticate, async (req, res) => {
  const { serviceId } = req.params;
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    // Delete service from services collection
    await admin.firestore().collection('services').doc(serviceId).delete();
    // Remove service ID from provider's services array
    await admin.firestore().collection('serviceProviders').doc(providerId).update({
      services: admin.firestore.FieldValue.arrayRemove(serviceId)
    });
    res.json({ success: true, message: 'Service deleted successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error deleting service', error });
  }
});

// View all services offered by the provider
app.get('/api/serviceProviders/services', authenticate, async (req, res) => {
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    const providerDoc = await admin.firestore().collection('serviceProviders').doc(providerId).get();
    if (providerDoc.exists) {
      const serviceIds = providerDoc.data().services;
      const services = [];
      for (const serviceId of serviceIds) {
        const serviceDoc = await admin.firestore().collection('services').doc(serviceId).get();
        if (serviceDoc.exists) {
          services.push(serviceDoc.data());
        }
      }
      res.json({ success: true, services });
    } else {
      res.status(404).json({ success: false, message: 'Provider not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error getting services', error });
  }
});

// --- USER ENDPOINTS ---

// Register a new user
app.post('/api/users/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  try {
    // Hash password before saving
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await admin.auth().createUser({
      email,
      password: hashedPassword,
    });
    await admin.firestore().collection('users').doc(user.uid).set({
      email,
      password: hashedPassword,
      firstName,
      lastName,
    });
    res.json({ success: true, message: 'User registered successfully!' });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error registering user', error });
  }
});

// User login
app.post('/api/users/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await admin.auth().getUserByEmail(email);
    if (user) {
      // Compare password with hashed password in Firestore
      const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
      if (isPasswordValid) {
        // Generate JWT token
        const token = jwt.sign({ uid: user.uid }, secretKey, { expiresIn: '1h' });
        res.json({ success: true, message: 'Login successful!', token });
      } else {
        res.status(401).json({ success: false, message: 'Incorrect password' });
      }
    } else {
      res.status(404).json({ success: false, message: 'User not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error logging in', error });
  }
});

// --- SERVICE REQUEST ENDPOINTS ---

// Create a new service request
app.post('/api/serviceRequests', authenticate, async (req, res) => {
  const { serviceId } = req.body;
  const userId = req.user.uid; // Get user ID from JWT
  try {
    const serviceRequestDoc = await admin.firestore().collection('serviceRequests').add({
      userId,
      serviceId,
      status: 'pending',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });
    res.json({ success: true, message: 'Service request created successfully!', requestId: serviceRequestDoc.id });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error creating service request', error });
  }
});

// Delete a service request
app.delete('/api/serviceRequests/:requestId', authenticate, async (req, res) => {
  const { requestId } = req.params;
  const userId = req.user.uid; // Get user ID from JWT
  try {
    const serviceRequestDoc = await admin.firestore().collection('serviceRequests').doc(requestId).get();
    if (serviceRequestDoc.exists && serviceRequestDoc.data().userId === userId) {
      await admin.firestore().collection('serviceRequests').doc(requestId).delete();
      res.json({ success: true, message: 'Service request deleted successfully!' });
    } else {
      res.status(403).json({ success: false, message: 'Unauthorized to delete this request' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error deleting service request', error });
  }
});

// --- ADDITIONAL ENDPOINTS (Optional) ---

// Get all service requests for a specific service provider
app.get('/api/serviceProviders/requests', authenticate, async (req, res) => {
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    const requests = [];
    const querySnapshot = await admin.firestore().collection('serviceRequests')
      .where('serviceId', 'in', (await admin.firestore().collection('serviceProviders').doc(providerId).get()).data().services)
      .get();
    querySnapshot.forEach(doc => {
      requests.push(doc.data());
    });
    res.json({ success: true, requests });
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error getting service requests', error });
  }
});

// Update the status of a service request (for service providers)
app.put('/api/serviceProviders/requests/:requestId', authenticate, async (req, res) => {
  const { requestId } = req.params;
  const { status } = req.body;
  const providerId = req.user.uid; // Get provider ID from JWT
  try {
    const serviceRequestDoc = await admin.firestore().collection('serviceRequests').doc(requestId).get();
    if (serviceRequestDoc.exists) {
      const serviceId = serviceRequestDoc.data().serviceId;
      const providerServices = (await admin.firestore().collection('serviceProviders').doc(providerId).get()).data().services;
      if (providerServices.includes(serviceId)) {
        await admin.firestore().collection('serviceRequests').doc(requestId).update({ status });
        res.json({ success: true, message: 'Service request status updated successfully!' });
      } else {
        res.status(403).json({ success: false, message: 'Unauthorized to update this request' });
      }
    } else {
      res.status(404).json({ success: false, message: 'Service request not found' });
    }
  } catch (error) {
    res.status(500).json({ success: false, message: 'Error updating service request status', error });
  }
});

// --- START THE SERVER ---

const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});

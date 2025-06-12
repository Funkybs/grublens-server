require('dotenv').config(); 
const express = require('express'); 
const multer = require('multer'); 
const cors = require('cors'); 
const OpenAI = require('openai'); 
const fs = require('fs').promises; 
const path = require('path'); 
const { google } = require('googleapis'); 
const crypto = require('crypto'); 
const admin = require('firebase-admin'); 

// Initialize Firebase with environment variables
const serviceAccount = { 
  type: "service_account", 
  project_id: process.env.FIREBASE_PROJECT_ID, 
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID, 
  private_key: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined, 
  client_email: process.env.FIREBASE_CLIENT_EMAIL, 
  client_id: process.env.FIREBASE_CLIENT_ID, 
  auth_uri: "https://accounts.google.com/o/oauth2/auth", 
  token_uri: "https://oauth2.googleapis.com/token", 
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs", 
  client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(process.env.FIREBASE_CLIENT_EMAIL || '')}` 
}; 

admin.initializeApp({ 
  credential: admin.credential.cert(serviceAccount), 
  storageBucket: 'grublens-storage.firebasestorage.app' 
}); 

const bucket = admin.storage().bucket(); 
const db = admin.firestore(); 

// Function to upload image to Firebase 
async function uploadImageToFirebase(imageUrl, recipeName) { 
  try { 
    const response = await fetch(imageUrl); 
    const arrayBuffer = await response.arrayBuffer(); 
    const buffer = Buffer.from(arrayBuffer); 
     
    const fileName = `recipe-images/${Date.now()}-${recipeName.replace(/[^a-z0-9]/gi, '-').toLowerCase()}.jpg`; 
    const file = bucket.file(fileName); 
     
    await file.save(buffer, { 
      metadata: { 
        contentType: 'image/jpeg', 
      }, 
    }); 
     
    await file.makePublic(); 
     
    return `https://storage.googleapis.com/${bucket.name}/${fileName}`; 
  } catch (error) { 
    console.error('Error uploading to Firebase:', error); 
    return imageUrl; 
  } 
} 

const app = express(); 
const PORT = process.env.PORT || 3000; 

app.use(cors()); 
app.use(express.json()); 
app.use(express.urlencoded({ extended: true })); 

// Configure multer for image uploads 
const storage = multer.diskStorage({ 
  destination: async (req, file, cb) => { 
    const uploadDir = 'uploads/'; 
    try { 
      await fs.mkdir(uploadDir, { recursive: true }); 
    } catch (error) { 
      console.error('Error creating upload directory:', error); 
    } 
    cb(null, uploadDir); 
  }, 
  filename: (req, file, cb) => { 
    const filename = Date.now() + path.extname(file.originalname); 
    console.log('Saving file as:', filename); 
    cb(null, filename); 
  } 
}); 

const upload = multer({  
  storage, 
  limits: { fileSize: 5 * 1024 * 1024 } 
}); 

// Initialize OpenAI 
const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY 
}); 

// In-memory image cache 
const imageCache = new Map(); 

// Cache management functions 
const getCachedImage = (recipeName, ingredients) => { 
  const key = crypto.createHash('md5').update(`${recipeName}-${ingredients.sort().join(',')}`).digest('hex'); 
  return imageCache.get(key); 
}; 

const cacheImage = (recipeName, ingredients, imageUrl) => { 
  const key = crypto.createHash('md5').update(`${recipeName}-${ingredients.sort().join(',')}`).digest('hex'); 
  imageCache.set(key, imageUrl); 
   
  if (imageCache.size > 1000) { 
    const firstKey = imageCache.keys().next().value; 
    imageCache.delete(firstKey); 
  } 
}; 

// User management functions with Firestore 
const getUserData = async (userId) => { 
  try { 
    const userDoc = await db.collection('users').doc(userId).get(); 
     
    if (!userDoc.exists) { 
      const newUser = { 
        id: userId, 
        subscriptionTier: 'free', 
        scansRemaining: 3, 
        scansUsed: 0, 
        lastResetDate: new Date(), 
        createdAt: new Date(), 
        updatedAt: new Date() 
      }; 
       
      await db.collection('users').doc(userId).set(newUser); 
      return newUser; 
    } 
     
    const userData = userDoc.data(); 
     
    // Check if month changed (reset scans for subscribers) 
    const now = new Date(); 
    const lastReset = new Date(userData.lastResetDate); 
    if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) { 
      const updates = { 
        lastResetDate: now, 
        updatedAt: now 
      }; 
       
      if (userData.subscriptionTier === 'basic') { 
        updates.scansRemaining = 15; 
      } else if (userData.subscriptionTier === 'premium') { 
        updates.scansRemaining = 40; 
      } 
       
      await db.collection('users').doc(userId).update(updates); 
      return { ...userData, ...updates }; 
    } 
     
    return userData; 
  } catch (error) { 
    console.error('Error getting user data:', error); 
    return { 
      id: userId, 
      subscriptionTier: 'free', 
      scansRemaining: 3 
    }; 
  } 
}; 

const updateUserScans = async (userId, decrement = true) => { 
  try { 
    const userRef = db.collection('users').doc(userId); 
     
    if (decrement) { 
      await userRef.update({ 
        scansRemaining: admin.firestore.FieldValue.increment(-1), 
        scansUsed: admin.firestore.FieldValue.increment(1), 
        updatedAt: new Date() 
      }); 
    } 
     
    const updated = await userRef.get(); 
    return updated.data(); 
  } catch (error) { 
    console.error('Error updating user scans:', error); 
  } 
}; 

// Rate limiting function with progressive restrictions 
const checkRateLimits = async (userId, ipAddress, userData) => { 
  try { 
    if (userData.subscriptionTier !== 'free') { 
      return { allowed: true }; 
    } 
     
    const ipHash = crypto.createHash('md5').update(ipAddress).digest('hex'); 
    const monthKey = `${new Date().getFullYear()}-${new Date().getMonth()}`; 
    const rateLimitDocId = `${ipHash}_${monthKey}`; 
     
    const rateLimitDoc = await db.collection('rateLimits').doc(rateLimitDocId).get(); 
    const scanCount = rateLimitDoc.exists ? rateLimitDoc.data().freeScansCount : 0; 
     
    const limits = { 
      gentle: 9,
      warning: 12,
      hard: 15
    }; 
     
    if (scanCount >= limits.hard) { 
      return { 
        allowed: false, 
        message: "You've used all available free scans this month. Subscribe to continue!", 
        forcePaywall: true, 
        scansUsedThisMonth: scanCount 
      }; 
    } 
     
    if (rateLimitDoc.exists) { 
      await db.collection('rateLimits').doc(rateLimitDocId).update({ 
        freeScansCount: admin.firestore.FieldValue.increment(1), 
        lastScan: new Date(), 
        userIds: admin.firestore.FieldValue.arrayUnion(userId) 
      }); 
    } else { 
      await db.collection('rateLimits').doc(rateLimitDocId).set({ 
        freeScansCount: 1, 
        firstScan: new Date(), 
        lastScan: new Date(), 
        ipHash: ipHash, 
        month: monthKey, 
        userIds: [userId] 
      }); 
    } 
     
    const newCount = scanCount + 1; 
     
    if (newCount >= limits.warning) { 
      return { 
        allowed: true, 
        message: `Only ${limits.hard - newCount} free scans left this month!`, 
        showWarning: true, 
        scansUsedThisMonth: newCount, 
        scansLeftThisMonth: limits.hard - newCount 
      }; 
    } else if (newCount >= limits.gentle) { 
      return { 
        allowed: true, 
        message: "Enjoying GrubLens? Upgrade for unlimited scans!", 
        showUpgradeHint: true, 
        scansUsedThisMonth: newCount 
      }; 
    } 
     
    return {  
      allowed: true, 
      scansUsedThisMonth: newCount 
    }; 
  } catch (error) { 
    console.error('Error checking rate limits:', error); 
    return { allowed: true }; 
  } 
}; 

// Google Play verification 
const verifyGooglePlayPurchase = async (purchaseToken, productId) => { 
  try { 
    const auth = new google.auth.GoogleAuth({ 
      keyFile: 'path/to/your-service-account-key.json', 
      scopes: ['https://www.googleapis.com/auth/androidpublisher'], 
    }); 

    const androidPublisher = google.androidpublisher({ 
      version: 'v3', 
      auth: auth, 
    }); 

    const res = await androidPublisher.purchases.subscriptions.get({ 
      packageName: 'com.grublens.app', 
      subscriptionId: productId, 
      token: purchaseToken, 
    }); 

    return res.data; 
  } catch (error) { 
    console.error('Play Store verification error:', error); 
    return null; 
  } 
}; 

// ENHANCED Apple receipt verification with extensive debugging
const verifyAppleReceipt = async (receiptData) => { 
  try { 
    console.log('🍎📄 ========== APPLE RECEIPT VERIFICATION START ==========');
    console.log('🍎📄 Timestamp:', new Date().toISOString());
    console.log('🍎📄 Receipt data provided:', !!receiptData);
    console.log('🍎📄 Receipt data type:', typeof receiptData);
    console.log('🍎📄 Receipt data length:', receiptData?.length || 'undefined');
    console.log('🍎📄 Receipt preview (first 100 chars):', receiptData?.substring(0, 100) || 'undefined');
    console.log('🍎📄 Apple shared secret configured:', !!process.env.APPLE_SHARED_SECRET);
    console.log('🍎📄 Apple shared secret length:', process.env.APPLE_SHARED_SECRET?.length || 'undefined');
    
    if (!receiptData) {
      console.log('🍎❌ FATAL: No receipt data provided to verifyAppleReceipt');
      return { status: 21002, error: 'No receipt data provided' };
    }
    
    if (!process.env.APPLE_SHARED_SECRET) {
      console.log('🍎❌ FATAL: No Apple shared secret configured');
      return { status: 21003, error: 'Apple shared secret not configured' };
    }
    
    // ALWAYS try production first
    console.log('🍎🏢 ========== TRYING PRODUCTION ENDPOINT ==========');
    console.log('🍎🏢 URL: https://buy.itunes.apple.com/verifyReceipt');
    console.log('🍎🏢 Sending request...');
    
    const productionRequestBody = {
      'receipt-data': receiptData,
      'password': process.env.APPLE_SHARED_SECRET
    };
    
    console.log('🍎🏢 Request body keys:', Object.keys(productionRequestBody));
    
    let response = await fetch('https://buy.itunes.apple.com/verifyReceipt', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(productionRequestBody)
    });
    
    console.log('🍎🏢 Production response status code:', response.status);
    console.log('🍎🏢 Production response headers:', JSON.stringify(response.headers, null, 2));
    
    let data = await response.json();
    console.log('🍎🏢 PRODUCTION RESPONSE STATUS:', data.status);
    console.log('🍎🏢 PRODUCTION FULL RESPONSE:');
    console.log(JSON.stringify(data, null, 2));
    
    // Handle different status codes
    if (data.status === 0) {
      console.log('🍎✅ PRODUCTION VERIFICATION SUCCESSFUL!');
      console.log('🍎✅ Latest receipt info entries:', data.latest_receipt_info?.length || 0);
      return data;
    }
    
    // Status 21007 means sandbox receipt sent to production
    if (data.status === 21007) {
      console.log('🍎🧪 ========== SANDBOX RECEIPT DETECTED ==========');
      console.log('🍎🧪 Production returned status 21007 - this is a sandbox receipt');
      console.log('🍎🧪 Switching to sandbox endpoint...');
      console.log('🍎🧪 URL: https://sandbox.itunes.apple.com/verifyReceipt');
      
      const sandboxRequestBody = {
        'receipt-data': receiptData,
        'password': process.env.APPLE_SHARED_SECRET
      };
      
      response = await fetch('https://sandbox.itunes.apple.com/verifyReceipt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(sandboxRequestBody)
      });
      
      console.log('🍎🧪 Sandbox response status code:', response.status);
      console.log('🍎🧪 Sandbox response headers:', JSON.stringify(response.headers, null, 2));
      
      data = await response.json();
      console.log('🍎🧪 SANDBOX RESPONSE STATUS:', data.status);
      console.log('🍎🧪 SANDBOX FULL RESPONSE:');
      console.log(JSON.stringify(data, null, 2));
      
      if (data.status === 0) {
        console.log('🍎✅ SANDBOX VERIFICATION SUCCESSFUL!');
        console.log('🍎✅ Latest receipt info entries:', data.latest_receipt_info?.length || 0);
      } else {
        console.log('🍎❌ SANDBOX VERIFICATION FAILED');
        console.log('🍎❌ Sandbox status code:', data.status);
      }
    } else {
      console.log('🍎❌ PRODUCTION VERIFICATION FAILED');
      console.log('🍎❌ Production status code:', data.status);
      console.log('🍎❌ Error details:', data);
    }
    
    console.log('🍎📄 ========== APPLE RECEIPT VERIFICATION END ==========');
    console.log('🍎📄 Final result status:', data.status);
    console.log('🍎📄 Final success:', data.status === 0 ? 'SUCCESS' : 'FAILED');
    
    return data;
  } catch (error) { 
    console.error('🍎💥 ========== APPLE RECEIPT VERIFICATION ERROR ==========');
    console.error('🍎💥 Error type:', error.name);
    console.error('🍎💥 Error message:', error.message);
    console.error('🍎💥 Error stack:', error.stack);
    console.error('🍎💥 =======================================================');
    return { status: 21000, error: error.message }; 
  } 
}; 

// MASSIVELY ENHANCED verify-purchase endpoint
app.post('/api/verify-purchase', async (req, res) => {
  console.log('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥');
  console.log('🔥🔥🔥           VERIFY-PURCHASE ENDPOINT HIT!           🔥🔥🔥');
  console.log('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥');
  console.log('📨 Request timestamp:', new Date().toISOString());
  console.log('📨 Request method:', req.method);
  console.log('📨 Request URL:', req.url);
  console.log('📨 Request IP:', req.ip || req.connection.remoteAddress || 'unknown');
  console.log('📨 User-Agent:', req.headers['user-agent'] || 'unknown');
  console.log('📨 Content-Type:', req.headers['content-type'] || 'unknown');
  console.log('📨 Request headers:');
  console.log(JSON.stringify(req.headers, null, 2));
  console.log('📨 Request body exists:', !!req.body);
  console.log('📨 Request body keys:', req.body ? Object.keys(req.body) : 'no body');
  
  try {
    const { purchaseToken, productId, userId, platform, receiptData } = req.body;
    
    console.log('🔍 ========== EXTRACTED REQUEST DATA ==========');
    console.log('🔍 purchaseToken:', purchaseToken ? `PROVIDED (${purchaseToken.length} chars)` : 'MISSING');
    console.log('🔍 productId:', productId || 'MISSING');
    console.log('🔍 userId:', userId || 'MISSING');
    console.log('🔍 platform:', platform || 'MISSING');
    console.log('🔍 receiptData:', receiptData ? `PROVIDED (${receiptData.length} chars)` : 'MISSING');
    
    if (receiptData) {
      console.log('📄 Receipt data preview (first 100 chars):');
      console.log(receiptData.substring(0, 100) + '...');
      console.log('📄 Receipt data ends with:', receiptData.substring(receiptData.length - 20));
    }
    
    // Validate required fields
    if (!userId) {
      console.log('❌ VALIDATION ERROR: Missing userId');
      return res.status(400).json({ valid: false, error: 'Missing userId' });
    }
    
    if (!platform) {
      console.log('❌ VALIDATION ERROR: Missing platform');
      return res.status(400).json({ valid: false, error: 'Missing platform' });
    }
    
    if (!productId) {
      console.log('❌ VALIDATION ERROR: Missing productId');
      return res.status(400).json({ valid: false, error: 'Missing productId' });
    }
    
    let isValid = false;
    let expiryTime = null;
    let tier = 'free';
    let permanentUserId = userId;
    
    if (platform === 'android') {
      console.log('🤖 ========== ANDROID VERIFICATION STARTING ==========');
      
      if (!purchaseToken) {
        console.log('❌ Android verification failed: No purchase token provided');
        return res.status(400).json({ valid: false, error: 'No purchase token provided for Android verification' });
      }
      
      console.log('🤖 Calling verifyGooglePlayPurchase...');
      const purchaseData = await verifyGooglePlayPurchase(purchaseToken, productId);
      console.log('🤖 Google Play response:', JSON.stringify(purchaseData, null, 2));
      
      isValid = purchaseData && purchaseData.paymentState === 1;
      expiryTime = purchaseData?.expiryTimeMillis;
      
      if (purchaseData?.obfuscatedAccountId) {
        permanentUserId = `gplay_${purchaseData.obfuscatedAccountId}`;
      }
      
      if (productId === 'com.grublens.basic') {
        tier = 'basic';
      } else if (productId === 'com.grublens.premium') {
        tier = 'premium';
      }
      
      console.log('🤖 Android verification result:', { isValid, tier, permanentUserId, expiryTime });
      
    } else if (platform === 'ios') {
      console.log('🍎 ========== iOS VERIFICATION STARTING ==========');
      
      if (!receiptData) {
        console.log('❌ iOS verification failed: No receipt data provided');
        return res.status(400).json({ 
          valid: false, 
          error: 'No receipt data provided for iOS verification' 
        });
      }
      
      console.log('🍎 Receipt data validation:');
      console.log('🍎 - Length:', receiptData.length);
      console.log('🍎 - Type:', typeof receiptData);
      console.log('🍎 - Is string:', typeof receiptData === 'string');
      console.log('🍎 - Is base64-like:', /^[A-Za-z0-9+/]*={0,2}$/.test(receiptData));
      
      console.log('🍎 Calling verifyAppleReceipt...');
      const verificationResult = await verifyAppleReceipt(receiptData);
      console.log('🍎 Apple verification complete. Status:', verificationResult?.status);
      
      if (verificationResult && verificationResult.status === 0) {
        console.log('✅ Apple verification SUCCESS!');
        isValid = true;
        
        const latestReceiptInfo = verificationResult.latest_receipt_info;
        console.log('📋 Latest receipt info available:', !!latestReceiptInfo);
        console.log('📋 Latest receipt info entries:', latestReceiptInfo?.length || 0);
        
        if (latestReceiptInfo && latestReceiptInfo.length > 0) {
          const latestPurchase = latestReceiptInfo[latestReceiptInfo.length - 1];
          console.log('📋 Latest purchase details:');
          console.log('📋 - Product ID:', latestPurchase.product_id);
          console.log('📋 - Original transaction ID:', latestPurchase.original_transaction_id);
          console.log('📋 - Expires date MS:', latestPurchase.expires_date_ms);
          console.log('📋 - Purchase date MS:', latestPurchase.purchase_date_ms);
          
          expiryTime = parseInt(latestPurchase.expires_date_ms);
          const currentTime = Date.now();
          console.log('⏰ Expiry time:', expiryTime);
          console.log('⏰ Current time:', currentTime);
          console.log('⏰ Time difference (hours):', (expiryTime - currentTime) / (1000 * 60 * 60));
          
          isValid = expiryTime > currentTime;
          console.log('✅ Subscription currently active:', isValid);
          
          if (latestPurchase.original_transaction_id) {
            permanentUserId = `apple_${latestPurchase.original_transaction_id}`;
            console.log('🆔 Permanent user ID from original_transaction_id:', permanentUserId);
          }
          
          if (latestPurchase.app_account_token) {
            permanentUserId = `apple_account_${latestPurchase.app_account_token}`;
            console.log('🆔 Permanent user ID from app_account_token:', permanentUserId);
          }
        } else {
          console.log('⚠️ No latest_receipt_info found in successful response');
        }
        
        // Determine tier based on product ID
        if (productId === 'com.grublens.basic') {
          tier = 'basic';
        } else if (productId === 'com.grublens.premium') {
          tier = 'premium';
        }
        
        console.log('🍎 iOS verification final result:', { isValid, tier, permanentUserId, expiryTime });
        
      } else {
        console.log('❌ Apple verification FAILED');
        console.log('❌ Status code:', verificationResult?.status);
        console.log('❌ Error details:', verificationResult?.error);
        
        // Log specific error meanings
        const errorMeanings = {
          21000: 'App Store could not read the receipt',
          21002: 'Receipt data was malformed or missing',
          21003: 'Receipt could not be authenticated',
          21004: 'Shared secret does not match',
          21005: 'Receipt server is not currently available',
          21006: 'Receipt is valid but subscription has expired',
          21007: 'Receipt is from sandbox but sent to production',
          21008: 'Receipt is from production but sent to sandbox'
        };
        
        const meaning = errorMeanings[verificationResult?.status] || 'Unknown error';
        console.log('❌ Error meaning:', meaning);
      }
    } else {
      console.log('❌ Unknown platform:', platform);
      return res.status(400).json({ valid: false, error: `Unknown platform: ${platform}` });
    }
    
    console.log('💰 ========== PURCHASE VALIDATION COMPLETE ==========');
    console.log('💰 Final validation result:', isValid);
    console.log('💰 Subscription tier:', tier);
    console.log('💰 Permanent user ID:', permanentUserId);
    console.log('💰 Expiry time:', expiryTime);
    
    if (isValid) {
      console.log('💰 PURCHASE IS VALID - Updating database...');
      
      // Handle user migration if needed
      if (permanentUserId !== userId) {
        console.log('🔄 ========== USER MIGRATION REQUIRED ==========');
        console.log('🔄 Migrating from:', userId);
        console.log('🔄 Migrating to:', permanentUserId);
        
        const currentUserData = await getUserData(userId);
        console.log('📊 Current user data:', JSON.stringify(currentUserData, null, 2));
        
        const newUserData = {
          id: permanentUserId,
          subscriptionTier: tier,
          subscriptionExpiry: expiryTime ? new Date(parseInt(expiryTime)) : null,
          scansRemaining: tier === 'premium' ? 40 : 15,
          scansUsed: currentUserData.scansUsed || 0,
          originalUserId: userId,
          platform: platform,
          createdAt: new Date(),
          updatedAt: new Date()
        };
        
        console.log('💾 Saving new user data:', JSON.stringify(newUserData, null, 2));
        await db.collection('users').doc(permanentUserId).set(newUserData, { merge: true });
        
        if (currentUserData) {
          console.log('🔗 Marking old account as migrated');
          await db.collection('users').doc(userId).update({
            migratedTo: permanentUserId,
            updatedAt: new Date()
          });
        }
      } else {
        console.log('📝 Updating existing user:', permanentUserId);
        const updateData = {
          subscriptionTier: tier,
          scansRemaining: tier === 'premium' ? 40 : 15,
          updatedAt: new Date()
        };
        
        if (expiryTime) {
          updateData.subscriptionExpiry = new Date(parseInt(expiryTime));
        }
        
        console.log('📝 Update data:', JSON.stringify(updateData, null, 2));
        await db.collection('users').doc(permanentUserId).update(updateData);
      }
      
      const responseData = {
        valid: true,
        expiryTime,
        tier,
        permanentUserId,
        scansRemaining: tier === 'premium' ? 40 : 15
      };
      
      console.log('✅ ========== SUCCESS RESPONSE ==========');
      console.log('✅ Response data:', JSON.stringify(responseData, null, 2));
      console.log('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥');
      
      res.json(responseData);
    } else {
      console.log('❌ ========== PURCHASE INVALID ==========');
      console.log('❌ Sending failure response');
      console.log('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥');
      
      res.json({ valid: false });
    }
  } catch (error) {
    console.error('💥 ========== VERIFICATION ERROR ==========');
    console.error('💥 Error type:', error.name);
    console.error('💥 Error message:', error.message);
    console.error('💥 Error stack:', error.stack);
    console.error('💥 Timestamp:', new Date().toISOString());
    console.error('🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥');
    
    res.status(500).json({ 
      error: 'Verification failed',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Enhanced recipe analysis endpoint with rate limiting 
app.post('/api/analyze-groceries', upload.single('image'), async (req, res) => { 
  try { 
    console.log('Received request to analyze groceries'); 
     
    if (!req.file) { 
      return res.status(400).json({ error: 'No image provided' }); 
    } 

    if (!process.env.OPENAI_API_KEY) { 
      console.error('OpenAI API key is missing!'); 
      return res.status(500).json({ error: 'OpenAI API key not configured' }); 
    } 

    const userId = req.body.userId || 'anonymous'; 
    const userData = await getUserData(userId); 
     
    const userIP = req.headers['x-forwarded-for'] ||  
                   req.connection.remoteAddress ||  
                   req.socket.remoteAddress || 
                   'unknown'; 
     
    const rateLimitCheck = await checkRateLimits(userId, userIP, userData); 
     
    if (!rateLimitCheck.allowed) { 
      await fs.unlink(req.file.path); 
       
      return res.status(403).json({  
        error: rateLimitCheck.message, 
        forcePaywall: true, 
        scansUsedThisMonth: rateLimitCheck.scansUsedThisMonth 
      }); 
    } 
     
    if (userData.scansRemaining <= 0 && userData.subscriptionTier === 'free') { 
      await fs.unlink(req.file.path); 
       
      return res.status(403).json({  
        error: 'No scans remaining', 
        scansRemaining: 0, 
        subscriptionTier: userData.subscriptionTier, 
        rateLimitWarning: rateLimitCheck.message, 
        showPaywall: rateLimitCheck.showWarning || true 
      }); 
    } 

    console.log('Processing image:', req.file.filename); 

    const imageBuffer = await fs.readFile(req.file.path); 
    const base64Image = imageBuffer.toString('base64'); 

    const response = await openai.chat.completions.create({ 
      model: "gpt-4-turbo", 
      max_tokens: 4000, 
      temperature: 0.7, 
      messages: [ 
        { 
          role: "system", 
          content: `You are a professional chef creating elegant, gourmet recipes in the style of Joanna Gaines - focusing on fresh, wholesome ingredients with a sophisticated farmhouse touch. 

CRITICAL RULE: Only use ingredients that are CLEARLY VISIBLE in the provided image. Identify ingredients precisely - for example, if you see tuna steaks, call them "tuna steaks" not "red peppers". If you see steak, identify the cut if possible. 

Your responses should be realistic, practical recipes based solely on the visible food items in the image. BE EXTREMELY PRECISE in identifying the ingredients shown.` 
        }, 
        { 
          role: "user", 
          content: [ 
            { 
              type: "text", 
              text: `Analyze this image of groceries and create 3 gourmet recipes that use ONLY the ingredients visible in the photo. 

${req.body?.preferences ? `Consider these dietary preferences: ${req.body.preferences}` : ''} 
${req.body?.instructions ? `Special instructions: ${req.body.instructions}` : ''} 

For each recipe, provide: 
- name: An elegant, appetizing recipe name 
- cookingTime: Total time (e.g., "45 minutes") 
- difficulty: Easy, Medium, or Hard 
- servings: Number of servings 
- ingredients: Detailed list with precise measurements (ONLY ingredients visible in the image) 
- instructions: Clear, professional step-by-step instructions 
- tips: Professional chef tips for best results 

Format as JSON array with these exact keys. Include ONLY ingredients that can be seen in the image.` 
            }, 
            { 
              type: "image_url", 
              image_url: { 
                url: `data:image/jpeg;base64,${base64Image}` 
              } 
            } 
          ] 
        } 
      ] 
    }); 

    console.log('OpenAI response received'); 

    await fs.unlink(req.file.path); 

    let recipes; 
    try { 
      const content = response.choices[0].message.content; 
      console.log('Raw OpenAI response:', content.substring(0, 200) + '...'); 
       
      const jsonMatch = content.match(/\[[\s\S]*\]/); 
      if (jsonMatch) { 
        recipes = JSON.parse(jsonMatch[0]); 
         
        recipes = recipes.map(recipe => { 
          return { 
            name: recipe.name || "Delicious Recipe", 
            cookingTime: recipe.cookingTime || "30 minutes", 
            difficulty: recipe.difficulty || "Medium", 
            servings: recipe.servings || 4, 
            ingredients: Array.isArray(recipe.ingredients) ? recipe.ingredients : ["Ingredients not specified"], 
            instructions: Array.isArray(recipe.instructions) ? recipe.instructions : ["Instructions not provided"], 
            tips: recipe.tips || "Enjoy your meal!" 
          }; 
        }); 
      } else { 
        throw new Error('No valid JSON found in response'); 
      } 
    } catch (parseError) { 
      console.error('Parse error:', parseError); 
      console.log('Full response:', response.choices[0].message.content); 
       
      recipes = [ 
        { 
          name: "Simple Ingredient Combination", 
          cookingTime: "30 minutes", 
          difficulty: "Easy", 
          servings: 4, 
          ingredients: [ 
            "Ingredients from your image" 
          ], 
          instructions: [ 
            "Combine all ingredients", 
            "Cook until ready", 
            "Serve and enjoy" 
          ], 
          tips: "Use the ingredients as shown in your image for best results" 
        } 
      ]; 
    } 

    console.log('Generating images for all users to maximize wow factor'); 
     
    const imageQuality = userData.subscriptionTier === 'premium' ? 'hd' : 'standard'; 
     
    for (const recipe of recipes) { 
      try { 
        const cachedImageUrl = getCachedImage(recipe.name, recipe.ingredients); 
         
        if (cachedImageUrl) { 
          console.log('Using cached image for:', recipe.name); 
          recipe.imageUrl = cachedImageUrl; 
        } else { 
          console.log('Generating image for:', recipe.name); 
           
          const ingredientsList = Array.isArray(recipe.ingredients)  
            ? recipe.ingredients.slice(0, 5).join(', ') 
            : 'various ingredients'; 
           
          const recipeImagePrompt = `Create a high-quality, professional food photograph  
            of ${recipe.name} in Joanna Gaines farmhouse style. The dish should be presented  
            on a rustic wooden table with soft natural lighting, garnished beautifully.  
            The recipe contains ${ingredientsList}. The photo should look like it belongs  
            in a premium cookbook, with shallow depth of field and professional food styling.`; 
           
          const imageResponse = await openai.images.generate({ 
            model: "dall-e-3", 
            prompt: recipeImagePrompt, 
            n: 1, 
            size: "1024x1024", 
            quality: imageQuality 
          }); 
           
          const dalleUrl = imageResponse.data[0].url; 
          console.log('DALL-E URL generated:', dalleUrl.substring(0, 30) + '...'); 

          const firebaseUrl = await uploadImageToFirebase(dalleUrl, recipe.name); 
          recipe.imageUrl = firebaseUrl; 
          console.log('Firebase URL:', firebaseUrl); 

          cacheImage(recipe.name, recipe.ingredients, firebaseUrl); 
        } 
      } catch (imageError) { 
        console.error('Image generation error:', imageError); 
      } 
    } 

    const updatedUserData = await updateUserScans(userId); 

    console.log('Sending recipes to client'); 
    res.json({  
      recipes, 
      scansRemaining: updatedUserData.scansRemaining, 
      subscriptionTier: updatedUserData.subscriptionTier, 
      rateLimitWarning: rateLimitCheck.message, 
      showUpgradeHint: rateLimitCheck.showUpgradeHint, 
      showWarning: rateLimitCheck.showWarning, 
      scansUsedThisMonth: rateLimitCheck.scansUsedThisMonth, 
      scansLeftThisMonth: rateLimitCheck.scansLeftThisMonth 
    }); 

  } catch (error) { 
    console.error('Error in analyze-groceries:', error); 
    console.error('Error details:', error.message); 
     
    res.status(500).json({  
      error: 'Failed to analyze groceries', 
      message: error.message, 
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined 
    }); 
  } 
}); 

// Endpoint to check user subscription status 
app.get('/api/user/:userId', async (req, res) => { 
  try { 
    const { userId } = req.params; 
    const userData = await getUserData(userId); 
     
    res.json({ 
      subscriptionTier: userData.subscriptionTier, 
      scansRemaining: userData.scansRemaining, 
      subscriptionExpiry: userData.subscriptionExpiry 
    }); 
  } catch (error) { 
    console.error('Error fetching user data:', error); 
    res.status(500).json({ error: 'Failed to fetch user data' }); 
  } 
}); 

// Health check endpoint 
app.get('/health', (req, res) => { 
  res.json({  
    status: 'ok',  
    timestamp: new Date(), 
    features: { 
      imageGeneration: true, 
      subscriptionTiers: true, 
      firebaseStorage: true, 
      rateLimiting: true, 
      iosSupport: true, 
      androidSupport: true,
      bundleReceiptSupport: true,
      enhancedDebugging: true
    } 
  }); 
}); 

// Enhanced test endpoint for debugging 
app.get('/api/test', (req, res) => { 
  res.json({  
    message: 'GrubLens API is working with enhanced debugging!', 
    hasOpenAIKey: !!process.env.OPENAI_API_KEY, 
    hasAppleSecret: !!process.env.APPLE_SHARED_SECRET, 
    keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 7) + '...' : 'Not set', 
    version: '2.0.0-bundle-receipt-enhanced',
    hasFirebase: !!admin.apps.length, 
    firebaseConfigured: !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL),
    debuggingLevel: 'MAXIMUM',
    bundleReceiptReady: true
  }); 
}); 

// Root path handler 
app.get('/', (req, res) => { 
  res.send('GrubLens API v2.0.0 - Bundle Receipt Support, Enhanced Debugging, and Apple Review Ready!'); 
}); 

app.listen(PORT, () => { 
  console.log(`🚀 GrubLens server running on port ${PORT}`); 
  console.log(`🔑 OpenAI API Key configured: ${!!process.env.OPENAI_API_KEY}`); 
  console.log(`🍎 Apple Shared Secret configured: ${!!process.env.APPLE_SHARED_SECRET}`); 
  console.log(`🔥 Firebase Storage configured: ${!!admin.apps.length}`); 
  console.log(`⏱️ Rate limiting enabled: true`); 
  console.log(`📱 Platform support: iOS + Android`); 
  console.log(`🧾 Bundle Receipt Support: ENABLED`);
  console.log(`🔍 Enhanced Debugging: MAXIMUM LEVEL`);
  console.log(`🍎 Apple Review Mode: PRODUCTION + SANDBOX FALLBACK`);
  console.log(`🎯 Ready for App Store approval!`);
}).on('error', (err) => { 
  console.error('Server error:', err); 
}); 

process.on('uncaughtException', (err) => { 
  console.error('Uncaught Exception:', err); 
});

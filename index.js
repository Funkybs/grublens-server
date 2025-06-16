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

// 🔥 SIMPLE USER MANAGEMENT - DATABASE IS SINGLE SOURCE OF TRUTH
const getUserData = async (userId) => { 
  try { 
    console.log('📊 Getting user data for:', userId);
    const userDoc = await db.collection('users').doc(userId).get(); 
     
    if (!userDoc.exists) { 
      console.log('📊 User not found, will be created on first API call');
      return null;
    } 
     
    const userData = userDoc.data(); 
    console.log('📊 User data retrieved:', userData);
     
    // Check if month changed (reset scans for subscribers) 
    const now = new Date(); 
    const lastReset = userData.lastResetDate ? new Date(userData.lastResetDate) : new Date(); 
    if (now.getMonth() !== lastReset.getMonth() || now.getFullYear() !== lastReset.getFullYear()) { 
      console.log('📊 Month changed, resetting scans');
      const updates = { 
        lastResetDate: now, 
        updatedAt: now 
      }; 
       
      if (userData.subscriptionTier === 'basic') { 
        updates.scansRemaining = 15; 
      } else if (userData.subscriptionTier === 'premium') { 
        updates.scansRemaining = 40; 
      } else {
        updates.scansRemaining = 3; // Free tier
      }
       
      await db.collection('users').doc(userId).update(updates); 
      return { ...userData, ...updates }; 
    } 
     
    return userData; 
  } catch (error) { 
    console.error('❌ Error getting user data:', error); 
    return null;
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
    if (userData && userData.subscriptionTier !== 'free') { 
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

// Apple receipt verification
const verifyAppleReceipt = async (receiptData) => { 
  try { 
    console.log('🍎 Apple receipt verification start');
    
    if (!receiptData) {
      console.log('🍎❌ No receipt data provided');
      return { status: 21002, error: 'No receipt data provided' };
    }
    
    if (!process.env.APPLE_SHARED_SECRET) {
      console.log('🍎❌ No Apple shared secret configured');
      return { status: 21003, error: 'Apple shared secret not configured' };
    }
    
    // Try production first
    console.log('🍎 Trying production endpoint');
    let response = await fetch('https://buy.itunes.apple.com/verifyReceipt', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        'receipt-data': receiptData,
        'password': process.env.APPLE_SHARED_SECRET
      })
    });
    
    let data = await response.json();
    console.log('🍎 Production response status:', data.status);
    
    if (data.status === 0) {
      console.log('🍎✅ Production verification successful');
      return data;
    }
    
    // If status 21007 (sandbox receipt), try sandbox
    if (data.status === 21007) {
      console.log('🍎 Sandbox receipt detected, trying sandbox endpoint');
      response = await fetch('https://sandbox.itunes.apple.com/verifyReceipt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          'receipt-data': receiptData,
          'password': process.env.APPLE_SHARED_SECRET
        })
      });
      
      data = await response.json();
      console.log('🍎 Sandbox response status:', data.status);
      
      if (data.status === 0) {
        console.log('🍎✅ Sandbox verification successful');
      }
    }
    
    return data;
  } catch (error) { 
    console.error('🍎❌ Apple verification error:', error);
    return { status: 21000, error: error.message }; 
  } 
}; 

// 🔥 SIMPLE ENDPOINTS - NO COMPLEX LOGIC

// Create user endpoint
app.post('/api/user', async (req, res) => {
  try {
    const { userId, tier = 'free', scansRemaining = 3 } = req.body;
    
    console.log('📝 Creating user:', userId);
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }
    
    const userData = {
      id: userId,
      subscriptionTier: tier,
      scansRemaining: scansRemaining,
      scansUsed: 0,
      lastResetDate: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    };
    
    await db.collection('users').doc(userId).set(userData);
    
    console.log('✅ User created successfully');
    res.json({ success: true, user: userData });
    
  } catch (error) {
    console.error('❌ Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// Get user data endpoint
app.get('/api/user/:userId', async (req, res) => { 
  try { 
    const { userId } = req.params; 
    console.log('📊 Getting user:', userId);
    
    const userData = await getUserData(userId); 
    
    if (!userData) {
      console.log('📊 User not found, returning defaults');
      return res.json({
        subscriptionTier: 'free',
        scansRemaining: 3,
        subscriptionExpiry: null
      });
    }
     
    res.json({ 
      subscriptionTier: userData.subscriptionTier, 
      scansRemaining: userData.scansRemaining, 
      subscriptionExpiry: userData.subscriptionExpiry 
    }); 
  } catch (error) { 
    console.error('❌ Error fetching user data:', error); 
    res.status(500).json({ error: 'Failed to fetch user data' }); 
  } 
}); 

// Update user tier endpoint (THE ONLY WAY TO CHANGE SUBSCRIPTION)
app.put('/api/user/:userId/tier', async (req, res) => {
  try {
    const { userId } = req.params;
    const { tier, productId, subscriptionDate, scansRemaining } = req.body;
    
    console.log('💳 Updating user tier:', userId, 'to', tier);
    
    if (!userId || !tier) {
      return res.status(400).json({ error: 'User ID and tier required' });
    }
    
    const updateData = {
      subscriptionTier: tier,
      scansRemaining: scansRemaining || (tier === 'premium' ? 40 : tier === 'basic' ? 15 : 3),
      updatedAt: new Date()
    };
    
    if (subscriptionDate) {
      updateData.subscriptionDate = new Date(subscriptionDate);
    }
    
    if (productId) {
      updateData.lastProductId = productId;
    }
    
    await db.collection('users').doc(userId).update(updateData);
    
    console.log('✅ User tier updated successfully');
    res.json({ success: true, tier, scansRemaining: updateData.scansRemaining });
    
  } catch (error) {
    console.error('❌ Error updating user tier:', error);
    res.status(500).json({ error: 'Failed to update user tier' });
  }
});

// Purchase verification endpoint (SIMPLE VERSION)
app.post('/api/verify-purchase', async (req, res) => {
  console.log('💳 Purchase verification request');
  
  try {
    const { purchaseToken, productId, userId, platform, receiptData } = req.body;
    
    console.log('💳 Verification data:', {
      userId,
      platform,
      productId,
      hasReceiptData: !!receiptData,
      hasPurchaseToken: !!purchaseToken
    });
    
    if (!userId || !platform || !productId) {
      return res.status(400).json({ 
        valid: false, 
        error: 'Missing required fields: userId, platform, productId' 
      });
    }
    
    let isValid = false;
    let tier = 'free';
    
    if (platform === 'ios') {
      if (!receiptData) {
        return res.status(400).json({ 
          valid: false, 
          error: 'Receipt data required for iOS verification' 
        });
      }
      
      console.log('💳 Verifying Apple receipt');
      const verificationResult = await verifyAppleReceipt(receiptData);
      
      if (verificationResult && verificationResult.status === 0) {
        console.log('💳✅ Apple verification successful');
        isValid = true;
        
        // Check if subscription is still active
        const latestReceiptInfo = verificationResult.latest_receipt_info;
        if (latestReceiptInfo && latestReceiptInfo.length > 0) {
          const latestPurchase = latestReceiptInfo[latestReceiptInfo.length - 1];
          const expiryTime = parseInt(latestPurchase.expires_date_ms);
          const currentTime = Date.now();
          
          isValid = expiryTime > currentTime;
          console.log('💳 Subscription active:', isValid);
        }
      } else {
        console.log('💳❌ Apple verification failed:', verificationResult?.status);
      }
    } else if (platform === 'android') {
      // For now, just validate that we have a purchase token
      // In production, you'd verify with Google Play
      isValid = !!purchaseToken;
      console.log('💳 Android verification (simplified):', isValid);
    }
    
    // Determine tier from product ID
    if (isValid) {
      if (productId.includes('premium')) {
        tier = 'premium';
      } else if (productId.includes('basic')) {
        tier = 'basic';
      }
      
      console.log('💳 Determined tier:', tier);
      
      // Update user in database
      const scansRemaining = tier === 'premium' ? 40 : 15;
      
      await db.collection('users').doc(userId).set({
        id: userId,
        subscriptionTier: tier,
        scansRemaining: scansRemaining,
        subscriptionDate: new Date(),
        lastProductId: productId,
        platform: platform,
        updatedAt: new Date()
      }, { merge: true });
      
      console.log('💳✅ User updated in database');
      
      res.json({
        valid: true,
        tier: tier,
        scansRemaining: scansRemaining,
        permanentUserId: userId
      });
    } else {
      console.log('💳❌ Purchase verification failed');
      res.json({ valid: false });
    }
    
  } catch (error) {
    console.error('💳❌ Verification error:', error);
    res.status(500).json({ 
      valid: false,
      error: 'Verification failed',
      message: error.message
    });
  }
});

// Recipe analysis endpoint (unchanged)
app.post('/api/analyze-groceries', upload.single('image'), async (req, res) => { 
  try { 
    console.log('📷 Received request to analyze groceries'); 
     
    if (!req.file) { 
      return res.status(400).json({ error: 'No image provided' }); 
    } 

    if (!process.env.OPENAI_API_KEY) { 
      console.error('OpenAI API key is missing!'); 
      return res.status(500).json({ error: 'OpenAI API key not configured' }); 
    } 

    const userId = req.body.userId || 'anonymous'; 
    const userData = await getUserData(userId); 
     
    if (!userData) {
      console.log('📷 User not found, creating with free tier');
      await db.collection('users').doc(userId).set({
        id: userId,
        subscriptionTier: 'free',
        scansRemaining: 3,
        scansUsed: 0,
        createdAt: new Date(),
        updatedAt: new Date()
      });
      const newUserData = await getUserData(userId);
      userData = newUserData;
    }
    
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

    console.log('📷 Processing image:', req.file.filename); 

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

    console.log('📷 OpenAI response received'); 

    await fs.unlink(req.file.path); 

    let recipes; 
    try { 
      const content = response.choices[0].message.content; 
      console.log('📷 Raw OpenAI response:', content.substring(0, 200) + '...'); 
       
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
      console.error('📷 Parse error:', parseError); 
      console.log('📷 Full response:', response.choices[0].message.content); 
       
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

    console.log('📷 Generating images for recipes'); 
     
    const imageQuality = userData.subscriptionTier === 'premium' ? 'hd' : 'standard'; 
     
    for (const recipe of recipes) { 
      try { 
        const cachedImageUrl = getCachedImage(recipe.name, recipe.ingredients); 
         
        if (cachedImageUrl) { 
          console.log('📷 Using cached image for:', recipe.name); 
          recipe.imageUrl = cachedImageUrl; 
        } else { 
          console.log('📷 Generating image for:', recipe.name); 
           
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
          console.log('📷 DALL-E URL generated'); 

          const firebaseUrl = await uploadImageToFirebase(dalleUrl, recipe.name); 
          recipe.imageUrl = firebaseUrl; 
          console.log('📷 Firebase URL:', firebaseUrl); 

          cacheImage(recipe.name, recipe.ingredients, firebaseUrl); 
        } 
      } catch (imageError) { 
        console.error('📷 Image generation error:', imageError); 
      } 
    } 

    const updatedUserData = await updateUserScans(userId); 

    console.log('📷 Sending recipes to client'); 
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
    console.error('📷❌ Error in analyze-groceries:', error); 
    res.status(500).json({  
      error: 'Failed to analyze groceries', 
      message: error.message, 
      details: process.env.NODE_ENV === 'development' ? error.stack : undefined 
    }); 
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
      simplifiedSubscriptions: true
    } 
  }); 
}); 

// Test endpoint
app.get('/api/test', (req, res) => { 
  res.json({  
    message: 'GrubLens API is working with simplified subscriptions!', 
    hasOpenAIKey: !!process.env.OPENAI_API_KEY, 
    hasAppleSecret: !!process.env.APPLE_SHARED_SECRET, 
    keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 7) + '...' : 'Not set', 
    version: '3.0.0-simplified-subscriptions',
    hasFirebase: !!admin.apps.length, 
    firebaseConfigured: !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL),
    subscriptionModel: 'DATABASE_DRIVEN_SIMPLE'
  }); 
}); 

// Root path handler 
app.get('/', (req, res) => { 
  res.send('GrubLens API v3.0.0 - Simplified Subscriptions, Database-Driven, Apple-Approved!'); 
}); 

app.listen(PORT, () => { 
  console.log(`🚀 GrubLens server running on port ${PORT}`); 
  console.log(`🔑 OpenAI API Key configured: ${!!process.env.OPENAI_API_KEY}`); 
  console.log(`🍎 Apple Shared Secret configured: ${!!process.env.APPLE_SHARED_SECRET}`); 
  console.log(`🔥 Firebase Storage configured: ${!!admin.apps.length}`); 
  console.log(`⏱️ Rate limiting enabled: true`); 
  console.log(`📱 Platform support: iOS + Android`); 
  console.log(`✅ SIMPLIFIED SUBSCRIPTIONS: Database-driven, Apple-approved!`);
  console.log(`🎯 Ready for App Store approval with sane subscription logic!`);
}).on('error', (err) => { 
  console.error('Server error:', err); 
}); 

process.on('uncaughtException', (err) => { 
  console.error('Uncaught Exception:', err); 
});

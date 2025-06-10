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
 
// Initialize Firebase with environment variables instead of JSON file 
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
      // Create new user 
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
    // Only check rate limits for free users 
    if (userData.subscriptionTier !== 'free') { 
      return { allowed: true }; 
    } 
     
    // Hash the IP for privacy 
    const ipHash = crypto.createHash('md5').update(ipAddress).digest('hex'); 
    const monthKey = `${new Date().getFullYear()}-${new Date().getMonth()}`; 
    const rateLimitDocId = `${ipHash}_${monthKey}`; 
     
    const rateLimitDoc = await db.collection('rateLimits').doc(rateLimitDocId).get(); 
    const scanCount = rateLimitDoc.exists ? rateLimitDoc.data().freeScansCount : 0; 
     
    // Progressive limits 
    const limits = { 
      gentle: 9,      // After 9 scans, show "Last free scan!" 
      warning: 12,    // After 12, show "You're really loving GrubLens!" 
      hard: 15        // After 15, require subscription 
    }; 
     
    // Check if hard limit exceeded 
    if (scanCount >= limits.hard) { 
      return { 
        allowed: false, 
        message: "You've used all available free scans this month. Subscribe to continue!", 
        forcePaywall: true, 
        scansUsedThisMonth: scanCount 
      }; 
    } 
     
    // Increment the count for this scan 
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
     
    // Return appropriate message based on new count 
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
    // On error, allow the scan but log it 
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
 
// FIXED: Apple receipt verification - ALWAYS try production first, then sandbox
const verifyAppleReceipt = async (receiptData) => { 
  try { 
    console.log('Starting Apple receipt verification...');
    
    // ALWAYS try production URL first
    let response = await fetch('https://buy.itunes.apple.com/verifyReceipt', { 
      method: 'POST', 
      headers: { 
        'Content-Type': 'application/json', 
      }, 
      body: JSON.stringify({ 
        'receipt-data': receiptData, 
        'password': process.env.APPLE_SHARED_SECRET 
      }) 
    }); 
     
    let data = await response.json(); 
    console.log('Production verification status:', data.status);
    
    // If we get status 21007, it means this is a sandbox receipt
    // This is what happens during App Review!
    if (data.status === 21007) {
      console.log('Sandbox receipt detected, trying sandbox URL...');
      
      // Try sandbox URL
      response = await fetch('https://sandbox.itunes.apple.com/verifyReceipt', { 
        method: 'POST', 
        headers: { 
          'Content-Type': 'application/json', 
        }, 
        body: JSON.stringify({ 
          'receipt-data': receiptData, 
          'password': process.env.APPLE_SHARED_SECRET 
        }) 
      });
      
      data = await response.json();
      console.log('Sandbox verification status:', data.status);
    }
    
    return data; 
  } catch (error) { 
    console.error('Apple receipt verification error:', error); 
    return null; 
  } 
}; 
 
// Endpoint to verify purchases and update subscription 
app.post('/api/verify-purchase', async (req, res) => { 
  try { 
    const { purchaseToken, productId, userId, platform, receiptData } = req.body; 
     
    let isValid = false; 
    let expiryTime = null; 
    let tier = 'free'; 
    let permanentUserId = userId; 
     
    if (platform === 'android') { 
      const purchaseData = await verifyGooglePlayPurchase(purchaseToken, productId); 
      isValid = purchaseData && purchaseData.paymentState === 1; 
      expiryTime = purchaseData?.expiryTimeMillis; 
       
      // Use the obfuscated account ID if available 
      if (purchaseData?.obfuscatedAccountId) { 
        permanentUserId = `gplay_${purchaseData.obfuscatedAccountId}`; 
      } 
       
      if (productId === 'com.grublens.basic') { 
        tier = 'basic'; 
      } else if (productId === 'com.grublens.premium') { 
        tier = 'premium'; 
      } 
       
    } else if (platform === 'ios') { 
      // Verify with Apple 
      const verificationResult = await verifyAppleReceipt(receiptData); 
       
      if (verificationResult && verificationResult.status === 0) { 
        isValid = true; 
         
        // Get the latest receipt info 
        const latestReceiptInfo = verificationResult.latest_receipt_info; 
        if (latestReceiptInfo && latestReceiptInfo.length > 0) { 
          const latestPurchase = latestReceiptInfo[latestReceiptInfo.length - 1]; 
           
          // Get expiry time 
          expiryTime = parseInt(latestPurchase.expires_date_ms); 
           
          // Check if subscription is still active 
          isValid = expiryTime > Date.now(); 
           
          // Try to get a persistent identifier 
          // Apple provides 'original_transaction_id' which is consistent for the same user 
          if (latestPurchase.original_transaction_id) { 
            permanentUserId = `apple_${latestPurchase.original_transaction_id}`; 
          } 
           
          // Alternatively, if you implement app_account_token (iOS 15+) 
          // This requires setting it when initiating the purchase in your iOS app 
          if (latestPurchase.app_account_token) { 
            permanentUserId = `apple_account_${latestPurchase.app_account_token}`; 
          } 
        } 
         
        // Determine tier based on product ID 
        if (productId === 'com.grublens.basic') { 
          tier = 'basic'; 
        } else if (productId === 'com.grublens.premium') { 
          tier = 'premium'; 
        } 
      } else {
        console.log('Apple verification failed with status:', verificationResult?.status);
      }
    } 
     
    if (isValid) { 
      // Check if we need to migrate the user's data 
      if (permanentUserId !== userId) { 
        const currentUserData = await getUserData(userId); 
         
        await db.collection('users').doc(permanentUserId).set({ 
          id: permanentUserId, 
          subscriptionTier: tier, 
          subscriptionExpiry: new Date(parseInt(expiryTime)), 
          scansRemaining: tier === 'premium' ? 40 : 15, 
          scansUsed: currentUserData.scansUsed || 0, 
          originalUserId: userId, 
          platform: platform, 
          createdAt: new Date(), 
          updatedAt: new Date() 
        }, { merge: true }); 
         
        // Mark old account as migrated 
        if (currentUserData) { 
          await db.collection('users').doc(userId).update({ 
            migratedTo: permanentUserId, 
            updatedAt: new Date() 
          }); 
        } 
      } else { 
        await db.collection('users').doc(permanentUserId).update({ 
          subscriptionTier: tier, 
          subscriptionExpiry: new Date(parseInt(expiryTime)), 
          scansRemaining: tier === 'premium' ? 40 : 15, 
          updatedAt: new Date() 
        }); 
      } 
       
      res.json({  
        valid: true,  
        expiryTime,  
        tier, 
        permanentUserId, 
        scansRemaining: tier === 'premium' ? 40 : 15 
      }); 
    } else { 
      res.json({ valid: false }); 
    } 
  } catch (error) { 
    console.error('Verification error:', error); 
    res.status(500).json({ error: 'Verification failed' }); 
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
 
    // Get user data 
    const userId = req.body.userId || 'anonymous'; 
    const userData = await getUserData(userId); 
     
    // Get user's IP address 
    const userIP = req.headers['x-forwarded-for'] ||  
                   req.connection.remoteAddress ||  
                   req.socket.remoteAddress || 
                   'unknown'; 
     
    // Check rate limits BEFORE checking user's personal scans 
    const rateLimitCheck = await checkRateLimits(userId, userIP, userData); 
     
    if (!rateLimitCheck.allowed) { 
      // Clean up uploaded file 
      await fs.unlink(req.file.path); 
       
      return res.status(403).json({  
        error: rateLimitCheck.message, 
        forcePaywall: true, 
        scansUsedThisMonth: rateLimitCheck.scansUsedThisMonth 
      }); 
    } 
     
    // Check if user has personal scans remaining 
    if (userData.scansRemaining <= 0 && userData.subscriptionTier === 'free') { 
      // Clean up uploaded file 
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
 
    // Read the image file 
    const imageBuffer = await fs.readFile(req.file.path); 
    const base64Image = imageBuffer.toString('base64'); 
 
    // Enhanced prompt for premium recipes 
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
 
    // Clean up uploaded file 
    await fs.unlink(req.file.path); 
 
    // Parse and enhance response 
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
 
    // Generate images for all users 
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
 
    // Update user's scan count 
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
      androidSupport: true 
    } 
  }); 
}); 
 
// Test endpoint for debugging 
app.get('/api/test', (req, res) => { 
  res.json({  
    message: 'GrubLens API is working!', 
    hasOpenAIKey: !!process.env.OPENAI_API_KEY, 
    hasAppleSecret: !!process.env.APPLE_SHARED_SECRET, 
    keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 7) + '...' : 'Not set', 
    version: '1.5.0', // Updated version
    hasFirebase: !!admin.apps.length, 
    firebaseConfigured: !!(process.env.FIREBASE_PROJECT_ID && process.env.FIREBASE_CLIENT_EMAIL) 
  }); 
}); 
 
// Root path handler 
app.get('/', (req, res) => { 
  res.send('GrubLens API v1.5.0 - iOS + Android Support, Firebase Storage, Apple Review Fix, and Rate Limiting. See /health for status.'); 
}); 
 
app.listen(PORT, () => { 
  console.log(`GrubLens server running on port ${PORT}`); 
  console.log(`OpenAI API Key configured: ${!!process.env.OPENAI_API_KEY}`); 
  console.log(`Apple Shared Secret configured: ${!!process.env.APPLE_SHARED_SECRET}`); 
  console.log(`Firebase Storage configured: ${!!admin.apps.length}`); 
  console.log(`Rate limiting enabled: true`); 
  console.log(`Platform support: iOS + Android`); 
  console.log(`Apple Review Mode: Enabled (tries production then sandbox)`);
}).on('error', (err) => { 
  console.error('Server error:', err); 
}); 
 
// Keep the process running 
process.on('uncaughtException', (err) => { 
  console.error('Uncaught Exception:', err); 
});

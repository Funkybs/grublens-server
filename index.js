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

// Initialize Firebase
const serviceAccount = require('./grublens-firebase-key.json');
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  storageBucket: 'grublens-storage.appspot.com'
});

const bucket = admin.storage().bucket();

// Function to upload image to Firebase
async function uploadImageToFirebase(imageUrl, recipeName) {
  try {
    const response = await fetch(imageUrl);
    const buffer = await response.buffer();
    
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
    return imageUrl; // Fallback to original URL
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
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Initialize OpenAI
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

// In-memory image cache
const imageCache = new Map();

// In-memory user database (replace with actual database in production)
const users = new Map();

// Cache management
const getCachedImage = (recipeName, ingredients) => {
  // Create a unique hash based on recipe name and ingredients
  const key = crypto.createHash('md5').update(`${recipeName}-${ingredients.sort().join(',')}`).digest('hex');
  return imageCache.get(key);
};

const cacheImage = (recipeName, ingredients, imageUrl) => {
  const key = crypto.createHash('md5').update(`${recipeName}-${ingredients.sort().join(',')}`).digest('hex');
  imageCache.set(key, imageUrl);
  
  // Limit cache size (remove oldest entries if too large)
  if (imageCache.size > 1000) {
    const firstKey = imageCache.keys().next().value;
    imageCache.delete(firstKey);
  }
};

// User management functions
const getUserData = async (userId) => {
  // In production, fetch from database
  if (!users.has(userId)) {
    // Create default user if not exists
    users.set(userId, {
      id: userId,
      subscriptionTier: 'free', // 'free', 'basic', or 'premium'
      scansRemaining: 3,        // Free users get 3 scans
      subscriptionDate: new Date()
    });
  }
  return users.get(userId);
};

const updateUserScans = async (userId, decrement = true) => {
  // In production, update in database
  const userData = await getUserData(userId);
  if (decrement) {
    userData.scansRemaining = Math.max(0, userData.scansRemaining - 1);
  }
  users.set(userId, userData);
  return userData;
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

// Endpoint to verify purchases and update subscription
app.post('/api/verify-purchase', async (req, res) => {
  try {
    const { purchaseToken, productId, userId, platform } = req.body;
    
    let isValid = false;
    let expiryTime = null;
    let tier = 'free';
    
    // Verify based on platform
    if (platform === 'android') {
      const purchaseData = await verifyGooglePlayPurchase(purchaseToken, productId);
      isValid = purchaseData && purchaseData.paymentState === 1;
      expiryTime = purchaseData?.expiryTimeMillis;
      
      // Determine tier based on productId
      if (productId === 'com.grublens.basic') {
        tier = 'basic';
      } else if (productId === 'com.grublens.premium') {
        tier = 'premium';
      }
    } else if (platform === 'ios') {
      // iOS verification would go here
      // For now, trust the client for testing
      isValid = true;
      expiryTime = Date.now() + (30 * 24 * 60 * 60 * 1000); // 30 days
      
      if (productId === 'com.grublens.basic') {
        tier = 'basic';
      } else if (productId === 'com.grublens.premium') {
        tier = 'premium';
      }
    }
    
    if (isValid) {
      // Update user subscription
      const userData = await getUserData(userId);
      userData.subscriptionTier = tier;
      userData.subscriptionExpiry = new Date(parseInt(expiryTime));
      
      // Reset scan count based on tier
      userData.scansRemaining = tier === 'premium' ? 40 : (tier === 'basic' ? 15 : 3);
      
      users.set(userId, userData);
      
      res.json({ 
        valid: true, 
        expiryTime, 
        tier,
        scansRemaining: userData.scansRemaining
      });
    } else {
      res.json({ valid: false });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Enhanced recipe analysis endpoint with image generation
app.post('/api/analyze-groceries', upload.single('image'), async (req, res) => {
  try {
    console.log('Received request to analyze groceries');
    
    if (!req.file) {
      return res.status(400).json({ error: 'No image provided' });
    }

    // Check if OpenAI API key exists
    if (!process.env.OPENAI_API_KEY) {
      console.error('OpenAI API key is missing!');
      return res.status(500).json({ error: 'OpenAI API key not configured' });
    }

    // Get user data
    const userId = req.body.userId || 'anonymous';
    const userData = await getUserData(userId);
    
    // Check if user has scans remaining
    if (userData.scansRemaining <= 0 && userData.subscriptionTier !== 'free') {
      return res.status(403).json({ 
        error: 'No scans remaining',
        scansRemaining: 0,
        subscriptionTier: userData.subscriptionTier
      });
    }

    console.log('Processing image:', req.file.filename);

    // Read the image file
    const imageBuffer = await fs.readFile(req.file.path);
    const base64Image = imageBuffer.toString('base64');

    // Enhanced prompt for premium recipes with improved instructions to only use visible ingredients
    const response = await openai.chat.completions.create({
      model: "gpt-4-turbo", // Changed to current best vision model
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
      
      // Extract JSON from the response
      const jsonMatch = content.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        recipes = JSON.parse(jsonMatch[0]);
        
        // Post-process recipes to ensure they have all required fields
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
      
      // Fallback recipes
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

    // IMPORTANT CHANGE: Generate images for ALL tiers (including free)
    console.log('Generating images for all users to maximize wow factor');
    
    // Get appropriate quality based on tier
    const imageQuality = userData.subscriptionTier === 'premium' ? 'hd' : 'standard';
    
    for (const recipe of recipes) {
      try {
        // Check cache first
        const cachedImageUrl = getCachedImage(recipe.name, recipe.ingredients);
        
        if (cachedImageUrl) {
          console.log('Using cached image for:', recipe.name);
          recipe.imageUrl = cachedImageUrl;
        } else {
          console.log('Generating image for:', recipe.name);
          
          const ingredientsList = Array.isArray(recipe.ingredients) 
            ? recipe.ingredients.slice(0, 5).join(', ') // Limit to 5 ingredients in prompt
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

          // Upload to Firebase for permanent storage
          const firebaseUrl = await uploadImageToFirebase(dalleUrl, recipe.name);
          recipe.imageUrl = firebaseUrl;
          console.log('Firebase URL:', firebaseUrl);

          // Cache the Firebase URL instead
          cacheImage(recipe.name, recipe.ingredients, firebaseUrl);
        }
      } catch (imageError) {
        console.error('Image generation error:', imageError);
        // Don't fail the whole request if image generation fails
      }
    }

    // Update user's scan count
    const updatedUserData = await updateUserScans(userId);

    console.log('Sending recipes to client');
    res.json({ 
      recipes,
      scansRemaining: updatedUserData.scansRemaining,
      subscriptionTier: updatedUserData.subscriptionTier
    });

  } catch (error) {
    console.error('Error in analyze-groceries:', error);
    console.error('Error details:', error.message);
    
    // Send proper JSON error response
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
      firebaseStorage: true
    }
  });
});

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'GrubLens API is working!',
    hasOpenAIKey: !!process.env.OPENAI_API_KEY,
    keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 7) + '...' : 'Not set',
    version: '1.2.0',
    hasFirebase: !!admin.apps.length
  });
});

// Root path handler
app.get('/', (req, res) => {
  res.send('GrubLens API is running with Firebase Storage. See /health for status.');
});

app.listen(PORT, () => {
  console.log(`GrubLens server running on port ${PORT}`);
  console.log(`OpenAI API Key configured: ${!!process.env.OPENAI_API_KEY}`);
  console.log(`Firebase Storage configured: ${!!admin.apps.length}`);
}).on('error', (err) => {
  console.error('Server error:', err);
});

// Keep the process running
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});

// Scheduled task to reset scan counts monthly (in production, use a proper scheduler)
// This is just a demonstration - in production use cron jobs or similar
const resetAllScanCounts = async () => {
  for (const [userId, userData] of users.entries()) {
    if (userData.subscriptionTier === 'premium') {
      userData.scansRemaining = 40;
    } else if (userData.subscriptionTier === 'basic') {
      userData.scansRemaining = 15;
    } else {
      userData.scansRemaining = 3; // Free tier
    }
    users.set(userId, userData);
  }
  console.log('Reset all scan counts');
};

// Uncomment to test the reset function
// setTimeout(resetAllScanCounts, 10000);

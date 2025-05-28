require('dotenv').config();
const express = require('express');
const multer = require('multer');
const cors = require('cors');
const OpenAI = require('openai');
const fs = require('fs').promises;
const path = require('path');
const { google } = require('googleapis');

const app = express();
const PORT = 3000;

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

// Endpoint to verify purchases
app.post('/api/verify-purchase', async (req, res) => {
  try {
    const { purchaseToken, productId } = req.body;
    
    const purchaseData = await verifyGooglePlayPurchase(purchaseToken, productId);
    
    if (purchaseData && purchaseData.paymentState === 1) {
      res.json({ valid: true, expiryTime: purchaseData.expiryTimeMillis });
    } else {
      res.json({ valid: false });
    }
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Verification failed' });
  }
});

// Enhanced recipe analysis endpoint
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

    console.log('Sending recipes to client');
    res.json({ recipes });

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

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date() });
});

// Test endpoint for debugging
app.get('/api/test', (req, res) => {
  res.json({ 
    message: 'GrubLens API is working!',
    hasOpenAIKey: !!process.env.OPENAI_API_KEY,
    keyPrefix: process.env.OPENAI_API_KEY ? process.env.OPENAI_API_KEY.substring(0, 7) + '...' : 'Not set',
    version: '1.0.1'
  });
});

app.listen(PORT, () => {
  console.log(`GrubLens server running on port ${PORT}`);
  console.log(`OpenAI API Key configured: ${!!process.env.OPENAI_API_KEY}`);
}).on('error', (err) => {
  console.error('Server error:', err);
});

// Keep the process running
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
});
// server.js - Complete rewrite with contract middleware
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const dns = require('dns');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { TransactionBlock } = require('@mysten/sui.js/transactions');
const { SuiClient } = require('@mysten/sui.js/client');
require('dotenv').config();

// Import the contract middleware
const contractMiddleware = require('./contractMiddleware');

// =============================================
// FORCE IPv4 CONNECTIONS FOR CONSISTENCY
// =============================================
// Override dns.lookup to force IPv4
const originalLookup = dns.lookup;
dns.lookup = (hostname, options, callback) => {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  options = options || {};
  options.family = 4; // Force IPv4
  return originalLookup(hostname, options, callback);
};

// Initialize Express app
const app = express();

// Setup logging
const LOG_DIRECTORY = path.join(__dirname, 'logs');
if (!fs.existsSync(LOG_DIRECTORY)) {
  fs.mkdirSync(LOG_DIRECTORY);
}

const logFile = path.join(LOG_DIRECTORY, `server-${new Date().toISOString().split('T')[0]}.log`);
const logStream = fs.createWriteStream(logFile, { flags: 'a' });

function log(level, message, data = null) {
  const timestamp = new Date().toISOString();
  let logMessage = `${timestamp} [${level}] ${message}`;
  
  if (data) {
    if (typeof data === 'object') {
      try {
        logMessage += ' ' + JSON.stringify(data);
      } catch (e) {
        logMessage += ' [Object cannot be stringified]';
      }
    } else {
      logMessage += ' ' + data;
    }
  }
  
  console.log(logMessage);
  logStream.write(logMessage + '\n');
}

const logger = {
  debug: (message, data) => log('DEBUG', message, data),
  info: (message, data) => log('INFO', message, data),
  warn: (message, data) => log('WARN', message, data),
  error: (message, data) => log('ERROR', message, data)
};

// Configure middleware
app.use(cors({
  origin: '*', // For development only - restrict in production
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'zklogin-jwt']
}));
app.use(express.json({ limit: '2mb' }));

// Make logger available to middleware
app.set('logger', logger);

// Set packageId for middleware to use
const PACKAGE_ID = process.env.PACKAGE_ID || '0xab310610823f47b2e4a58a1987114793514d63605826a766b0c2dd4bd2b6d3d3';
app.set('packageId', PACKAGE_ID);

// Add the contract middleware
app.use(contractMiddleware);

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  // Don't log full request body for sensitive endpoints
  const sensitiveEndpoints = ['/api/enoki/create-session', '/api/enoki/create-zkp'];
  const isSensitive = sensitiveEndpoints.some(endpoint => req.path.includes(endpoint));
  
  const logData = {
    ip: req.ip,
    method: req.method,
    path: req.path,
    query: req.query,
    userAgent: req.headers['user-agent']
  };
  
  // Only log request body for non-sensitive endpoints
  if (!isSensitive && req.method !== 'GET') {
    logData.body = req.body;
  }
  
  logger.info(`Incoming ${req.method} request to ${req.path}`, logData);
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const level = res.statusCode >= 400 ? 'WARN' : 'INFO';
    
    log(level, `${req.method} ${req.path} - ${res.statusCode} (${duration}ms)`);
  });
  
  next();
});

// =============================================
// SUI ADDRESS UTILITIES
// =============================================
// Check if a string is a valid Sui address
function isValidSuiAddress(address) {
  if (!address || typeof address !== 'string') return false;
  
  // Must start with 0x
  if (!address.startsWith('0x')) return false;
  
  // Remove the 0x prefix and check length and content
  const addressWithoutPrefix = address.slice(2);
  return addressWithoutPrefix.length === 64 && /^[0-9a-fA-F]{64}$/.test(addressWithoutPrefix);
}

// =============================================
// ENOKI API INTEGRATION
// =============================================
// Constants and environment variables
const ENOKI_API_URL = 'https://api.enoki.mystenlabs.com';
const ENOKI_SECRET_KEY = process.env.ENOKI_SECRET_KEY;
const ENOKI_PUBLIC_KEY = process.env.NEXT_PUBLIC_ENOKI_API_KEY;
const NETWORK = process.env.SUI_NETWORK || 'testnet';

// Check for required environment variables
if (!ENOKI_SECRET_KEY) {
  logger.error('ENOKI_SECRET_KEY is not defined in environment variables');
  logger.warn('Using fallback wallet implementation due to missing API keys');
}

if (!PACKAGE_ID) {
  logger.warn('PACKAGE_ID is not defined in environment variables');
  logger.warn('Smart contract interactions will not work correctly without a package ID');
}

// Configure SUI client based on network
let SUI_RPC_URL;
switch (NETWORK) {
  case 'mainnet':
    SUI_RPC_URL = 'https://fullnode.mainnet.sui.io:443';
    break;
  case 'testnet':
    SUI_RPC_URL = 'https://fullnode.testnet.sui.io:443';
    break;
  case 'devnet':
    SUI_RPC_URL = 'https://fullnode.devnet.sui.io:443';
    break;
  default:
    SUI_RPC_URL = 'https://fullnode.testnet.sui.io:443';
    logger.warn(`Unknown network: ${NETWORK}, using testnet as default`);
}

// Create Sui client
const suiClient = new SuiClient({ url: SUI_RPC_URL });

// Create a properly authenticated Axios instance for Enoki API
function createEnokiAxiosInstance(token = null, additionalHeaders = {}) {
  const authToken = token || ENOKI_SECRET_KEY;
  
  logger.info('Creating Enoki Axios instance', { 
    hasToken: !!authToken,
    tokenType: token ? 'custom' : 'default',
    tokenLength: authToken?.length || 0,
    tokenPrefix: authToken ? authToken.substring(0, 10) + '...' : null,
    baseURL: ENOKI_API_URL,
    additionalHeadersCount: Object.keys(additionalHeaders).length,
    additionalHeaderNames: Object.keys(additionalHeaders)
  });
  
  const headers = {
    'Authorization': `Bearer ${authToken}`,
    'Content-Type': 'application/json',
    ...additionalHeaders
  };
  
  // Remove any undefined or null headers
  Object.keys(headers).forEach(key => {
    if (headers[key] === undefined || headers[key] === null) {
      delete headers[key];
      logger.warn(`Removed invalid header: ${key}`);
    }
  });
  
  logger.info('Final headers for Enoki API', {
    headerKeys: Object.keys(headers),
    hasAuthHeader: !!headers['Authorization'],
    hasJwt: !!headers['zklogin-jwt']
  });
  
  // Create Axios instance with interceptors for logging
  const axiosInstance = axios.create({
    baseURL: ENOKI_API_URL,
    headers,
    httpAgent: new http.Agent({ family: 4 }),
    httpsAgent: new https.Agent({ family: 4 }),
    timeout: 15000
  });
  
  // Add request interceptor for logging
  axiosInstance.interceptors.request.use((config) => {
    logger.info(`Enoki API request: ${config.method?.toUpperCase()} ${config.url}`, {
      method: config.method,
      url: config.url,
      baseURL: config.baseURL,
      timeout: config.timeout,
      hasData: !!config.data,
      dataSize: config.data ? JSON.stringify(config.data).length : 0,
      headers: {
        hasAuth: !!config.headers['Authorization'],
        hasJwt: !!config.headers['zklogin-jwt'],
        contentType: config.headers['Content-Type']
      }
    });
    return config;
  }, (error) => {
    logger.error('Error in Enoki API request interceptor', {
      message: error.message,
      stack: error.stack
    });
    return Promise.reject(error);
  });
  
  // Add response interceptor for logging
  axiosInstance.interceptors.response.use((response) => {
    logger.info(`Enoki API response: ${response.status} ${response.statusText}`, {
      status: response.status,
      statusText: response.statusText,
      requestUrl: response.config.url,
      requestMethod: response.config.method,
      dataSize: response.data ? JSON.stringify(response.data).length : 0,
      dataKeys: response.data ? Object.keys(response.data) : [],
      headers: response.headers
    });
    return response;
  }, (error) => {
    logger.error('Error in Enoki API response', {
      message: error.message,
      code: error.code,
      status: error.response?.status,
      statusText: error.response?.statusText,
      requestUrl: error.config?.url,
      requestMethod: error.config?.method,
      responseData: error.response?.data,
      stack: error.stack
    });
    return Promise.reject(error);
  });
  
  return axiosInstance;
}

// Basic retry functionality for API calls with enhanced logging
async function retryableRequest(apiCall, maxRetries = 2) {
  let retryCount = 0;
  let lastError = null;
  
  while (retryCount <= maxRetries) {
    try {
      logger.info(`API call attempt ${retryCount + 1}`);
      const startTime = Date.now();
      const result = await apiCall();
      const duration = Date.now() - startTime;
      
      logger.info(`API call successful on attempt ${retryCount + 1}`, {
        duration: `${duration}ms`,
        resultStatus: result.status,
        resultStatusText: result.statusText,
        dataSize: result.data ? JSON.stringify(result.data).length : 0
      });
      
      return result;
    } catch (error) {
      lastError = error;
      const responseData = error.response?.data;
      
      logger.error(`Attempt ${retryCount + 1} failed`, { 
        message: error.message,
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: responseData ? JSON.stringify(responseData).substring(0, 500) : null,
        code: error.code,
        stack: error.stack,
        url: error.config?.url,
        method: error.config?.method
      });
      
      retryCount++;
      
      if (retryCount <= maxRetries) {
        const delayMs = 1000 * Math.pow(2, retryCount - 1);
        logger.info(`Retrying in ${delayMs}ms...`);
        await new Promise(resolve => setTimeout(resolve, delayMs));
      }
    }
  }
  
  logger.error(`All ${maxRetries + 1} attempts failed`, {
    finalError: lastError.message,
    finalStatus: lastError.response?.status
  });
  
  throw lastError;
}

// New detailed debug endpoint for Enoki API
app.get('/api/enoki/debug-transaction', async (req, res) => {
  try {
    logger.info('Running detailed Enoki transaction debugging');
    
    const sampleParams = {
      targetExercises: 30,
      durationDays: 30
    };
    
    // Generate a test token
    const testToken = "test_token_" + Date.now();
    
    const results = {
      timestamp: new Date().toISOString(),
      environment: {
        ENOKI_SECRET_KEY_LENGTH: ENOKI_SECRET_KEY ? ENOKI_SECRET_KEY.length : 0,
        ENOKI_SECRET_KEY_PREFIX: ENOKI_SECRET_KEY ? ENOKI_SECRET_KEY.substring(0, 8) + '...' : null,
        ENOKI_PUBLIC_KEY_LENGTH: ENOKI_PUBLIC_KEY ? ENOKI_PUBLIC_KEY.length : 0,
        PACKAGE_ID: PACKAGE_ID,
        SUI_NETWORK: NETWORK,
        NODE_ENV: process.env.NODE_ENV
      },
      tests: {}
    };
    
    // Test 1: Build a transaction without executing it
    try {
      logger.info('Test 1: Building transaction');
      
      const tx = new TransactionBlock();
      
      // Add a move call
      tx.moveCall({
        target: `${PACKAGE_ID}::boar_challenge::init_pool`,
        arguments: [
          tx.pure(sampleParams.targetExercises),
          tx.pure(sampleParams.durationDays),
          tx.object('0x6'),
        ],
      });
      
      // Try to build it
      const txBytes = await tx.build({ client: suiClient });
      const txBase64 = Buffer.from(txBytes).toString('base64');
      
      results.tests.buildTransaction = {
        success: true,
        txBytesLength: txBytes.length,
        txBase64Length: txBase64.length,
        txBase64Prefix: txBase64.substring(0, 20) + '...'
      };
    } catch (buildError) {
      results.tests.buildTransaction = {
        success: false,
        error: buildError.message,
        stack: buildError.stack
      };
    }
    
    // Test 2: Verify Enoki API connectivity
    try {
      logger.info('Test 2: Verifying Enoki API connection');
      
      // Create an axios instance
      const enokiAxios = createEnokiAxiosInstance();
      
      // Try a simple request
      const apiResponse = await enokiAxios.get('/v1/app', {
        timeout: 5000
      });
      
      results.tests.enokiConnection = {
        success: true,
        status: apiResponse.status,
        dataKeys: Object.keys(apiResponse.data || {}),
        appInfo: apiResponse.data.data
      };
    } catch (apiError) {
      results.tests.enokiConnection = {
        success: false,
        status: apiError.response?.status,
        statusText: apiError.response?.statusText,
        error: apiError.message,
        data: apiError.response?.data,
        stack: apiError.stack
      };
    }
    
    // Test 3: Try a sponsoring request with mock data
    try {
      logger.info('Test 3: Testing sponsoring request');
      
      // Create a small transaction
      const tx = new TransactionBlock();
      
      tx.moveCall({
        target: `${PACKAGE_ID}::counter::create`,
        arguments: [tx.pure(123)],
      });
      
      // Build it
      const txBytes = await tx.build({ client: suiClient });
      const txBase64 = Buffer.from(txBytes).toString('base64');
      
      // Try to sponsor it
      const enokiAxios = createEnokiAxiosInstance();
      
      try {
        const sponsorResponse = await enokiAxios.post('/v1/transaction-blocks/sponsor', {
          network: NETWORK,
          transactionBlockKindBytes: txBase64
        }, {
          timeout: 10000
        });
        
        results.tests.sponsorTransaction = {
          success: true,
          status: sponsorResponse.status,
          dataKeys: Object.keys(sponsorResponse.data || {}),
          digest: sponsorResponse.data.data?.digest
        };
      } catch (sponsorError) {
        // Detailed sponsor error information
        results.tests.sponsorTransaction = {
          success: false,
          status: sponsorError.response?.status,
          statusText: sponsorError.response?.statusText,
          error: sponsorError.message,
          data: sponsorError.response?.data,
          stack: sponsorError.stack,
          request: {
            url: sponsorError.config?.url,
            method: sponsorError.config?.method,
            headers: sponsorError.config?.headers,
            hasData: !!sponsorError.config?.data,
            dataSize: sponsorError.config?.data ? JSON.stringify(sponsorError.config.data).length : 0
          }
        };
      }
    } catch (testError) {
      results.tests.sponsorTransaction = {
        success: false,
        phase: 'pre-sponsor',
        error: testError.message,
        stack: testError.stack
      };
    }
    
    // Test 4: Check Enoki portal config
    try {
      logger.info('Test 4: Testing Enoki portal configuration');
      
      const enokiAxios = createEnokiAxiosInstance();
      
      // Get app info to check move call targets
      const appResponse = await enokiAxios.get('/v1/app');
      
      // Check if we can get the move call targets
      const appData = appResponse.data.data;
      
      results.tests.portalConfig = {
        success: true,
        status: appResponse.status,
        appData: {
          hasAuthProviders: Array.isArray(appData.authenticationProviders),
          authProvidersCount: Array.isArray(appData.authenticationProviders) ? appData.authenticationProviders.length : 0,
          hasAllowedOrigins: Array.isArray(appData.allowedOrigins),
          allowedOriginsCount: Array.isArray(appData.allowedOrigins) ? appData.allowedOrigins.length : 0
        }
      };
      
      // We can't directly get the move call targets, but we can log what we found
      logger.info('App configuration from Enoki portal', {
        authProvidersCount: Array.isArray(appData.authenticationProviders) ? appData.authenticationProviders.length : 0,
        allowedOriginsCount: Array.isArray(appData.allowedOrigins) ? appData.allowedOrigins.length : 0
      });
    } catch (configError) {
      results.tests.portalConfig = {
        success: false,
        status: configError.response?.status,
        statusText: configError.response?.statusText,
        error: configError.message,
        data: configError.response?.data,
        stack: configError.stack
      };
    }
    
    // Generate recommendations based on test results
    const recommendations = [];
    
    if (!results.tests.buildTransaction?.success) {
      recommendations.push('Transaction building failed. Check the package ID in your .env file.');
    }
    
    if (!results.tests.enokiConnection?.success) {
      recommendations.push('Enoki API connection failed. Verify your API key and network connectivity.');
    } else if (!results.tests.sponsorTransaction?.success) {
      if (results.tests.sponsorTransaction.status === 401 || results.tests.sponsorTransaction.status === 403) {
        recommendations.push('Authentication failed for sponsoring transactions. Verify your private API key has sponsoring permissions.');
      } else if (results.tests.sponsorTransaction.status === 400) {
        recommendations.push('Invalid request for sponsoring transactions. Your API key might not have the correct permissions or the move call target is not allowed.');
      } else if (results.tests.sponsorTransaction.status === 500) {
        recommendations.push('Server error for sponsoring transactions. Make sure your move call targets are correctly configured in the Enoki portal.');
      }
    }
    
    // Add suggestion to check Enoki portal config
    recommendations.push('Verify these exact move call targets are added in your Enoki portal:');
    recommendations.push(`${PACKAGE_ID}::boar_challenge::init_pool`);
    recommendations.push(`${PACKAGE_ID}::counter::create`);
    
    results.recommendations = recommendations;
    
    logger.info('Debug tests completed', {
      buildSuccess: results.tests.buildTransaction?.success,
      connectionSuccess: results.tests.enokiConnection?.success,
      sponsorSuccess: results.tests.sponsorTransaction?.success,
      recommendationsCount: recommendations.length
    });
    
    res.json(results);
  } catch (error) {
    logger.error('Failed to complete debug tests', { 
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      error: 'Failed to complete debug tests',
      message: error.message,
      stack: error.stack
    });
  }
});

// Generate a deterministic fallback wallet - FIXED to create valid Sui addresses
function generateDeterministicWallet(seed = null) {
  // Use seed for deterministic generation or random if not provided
  const baseSeed = seed || Math.random().toString(36).substring(2, 15);
  
  // Create SHA-256 hash from seed for better randomness
  const hash = crypto.createHash('sha256').update(baseSeed).digest('hex');
  
  // Format as Sui address - 0x followed by 64 hex chars (CORRECT)
  const address = '0x' + hash.substring(0, 64);
  
  // Generate keypair ID (also deterministic from seed)
  const keypairId = 'key_' + crypto.createHash('sha256').update(baseSeed + '_keypair').digest('hex').substring(0, 16);
  
  return {
    userAddress: address,
    keypairId: keypairId,
    salt: crypto.createHash('sha256').update(baseSeed + '_salt').digest('hex').substring(0, 16),
    isFallback: true,
    generatedFrom: baseSeed.substring(0, 5) + '...'
  };
}

// In-memory cache for session info
const sessionCache = new Map();

// Cache session info
function cacheSessionInfo(token, userInfo) {
  if (!token) return;
  
  sessionCache.set(token, {
    ...userInfo,
    timestamp: Date.now()
  });
  
  // Automatically clear old sessions (keep cache size manageable)
  if (sessionCache.size > 1000) {
    const oldestEntry = [...sessionCache.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)[0];
    
    if (oldestEntry) {
      sessionCache.delete(oldestEntry[0]);
    }
  }
}

// Get cached session info
function getCachedSessionInfo(token) {
  if (!token) return null;
  
  const cached = sessionCache.get(token);
  
  // Return null if not found or too old (1 hour)
  if (!cached || (Date.now() - cached.timestamp > 3600000)) {
    return null;
  }
  
  return cached;
}

// =============================================
// HEALTH CHECK ENDPOINTS
// =============================================
// Basic health check
app.get('/health', (req, res) => {
  logger.info('Root health check requested');
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString()
  });
});

// API health check
app.get('/api/health', (req, res) => {
  logger.info('API health check requested');
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    api: 'enoki-backend',
    version: '3.0.0'
  });
});

// Enoki status endpoint
app.get('/api/enoki/status', async (req, res) => {
  try {
    logger.info('Checking Enoki API status');
    
    if (!ENOKI_SECRET_KEY) {
      return res.json({
        status: 'unavailable',
        reason: 'missing_api_key',
        usingFallback: true,
        message: 'API key not configured, using fallback wallet implementation',
        timestamp: new Date().toISOString()
      });
    }
    
    // Try to get app metadata - simple endpoint for testing authentication
    const enokiAxios = createEnokiAxiosInstance();
    
    try {
      const response = await enokiAxios.get('/v1/app');
      
      // Extract useful information from the app info
      const appInfo = response.data.data;
      const authProviders = appInfo.authenticationProviders || [];
      const googleProvider = authProviders.find(p => p.providerType === 'google');
      
      res.json({
        status: 'available',
        usingFallback: false,
        message: 'Enoki API is available and authentication is working',
        appInfo: {
          ...appInfo,
          hasGoogleProvider: !!googleProvider,
          googleClientId: googleProvider?.clientId
        },
        timestamp: new Date().toISOString()
      });
    } catch (apiError) {
      // Check if it's an authentication error
      if (apiError.response && (apiError.response.status === 401 || apiError.response.status === 403)) {
        res.json({
          status: 'unauthorized',
          usingFallback: true,
          message: 'API key is invalid or unauthorized',
          error: apiError.response.data,
          timestamp: new Date().toISOString()
        });
      } else {
        res.json({
          status: 'error',
          usingFallback: true,
          message: 'Error connecting to Enoki API',
          error: apiError.message,
          details: apiError.response?.data,
          timestamp: new Date().toISOString()
        });
      }
    }
  } catch (error) {
    logger.error('Error checking Enoki status', { error: error.message });
    res.status(500).json({ 
      status: 'error',
      error: 'Failed to check Enoki status' 
    });
  }
});

// =============================================
// ADDRESS VALIDATION ENDPOINTS
// =============================================
// Endpoint to validate a Sui address
app.get('/api/wallet/validate', async (req, res) => {
  try {
    const { address } = req.query;
    
    if (!address) {
      return res.status(400).json({ 
        valid: false,
        error: 'Address parameter is required'
      });
    }
    
    const isValid = isValidSuiAddress(address);
    
    return res.json({
      address,
      valid: isValid,
      length: address.length,
      hexLength: address.startsWith('0x') ? address.length - 2 : null,
      format: address.startsWith('0x') ? 'Starts with 0x' : 'Missing 0x prefix',
      expectedLength: 66, // 0x + 64 hex chars
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error validating address:', error);
    return res.status(500).json({ error: 'Error validating address' });
  }
});

// Debug endpoint for wallet generation
app.get('/api/debug/wallet-generation', (req, res) => {
  try {
    const seed = req.query.seed || 'test_seed_' + Date.now();
    
    // Generate a wallet with the current implementation
    const wallet = generateDeterministicWallet(seed);
    
    // Validate the address
    const isValid = isValidSuiAddress(wallet.userAddress);
    
    res.json({
      seed,
      wallet,
      validation: {
        isValid,
        addressLength: wallet.userAddress.length,
        hexLength: wallet.userAddress.startsWith('0x') ? wallet.userAddress.length - 2 : null,
        format: wallet.userAddress.startsWith('0x') ? 'Starts with 0x' : 'Missing 0x prefix',
        expectedFormat: '0x + 64 hex characters'
      },
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logger.error('Error in wallet generation debug:', error);
    res.status(500).json({ error: 'Error in wallet generation' });
  }
});

// =============================================
// ENOKI API ENDPOINTS
// =============================================

// Get zkLogin nonce with proper parameters
app.post('/api/enoki/zklogin-nonce', async (req, res) => {
  try {
    const { ephemeralPublicKey, network = NETWORK, additionalEpochs = 2 } = req.body;
    
    if (!ephemeralPublicKey) {
      return res.status(400).json({ 
        error: 'Missing required parameter', 
        details: 'ephemeralPublicKey is required' 
      });
    }
    
    logger.info('Getting Enoki zkLogin nonce', { 
      keyLength: ephemeralPublicKey.length,
      network,
      additionalEpochs 
    });
    
    if (!ENOKI_SECRET_KEY) {
      logger.warn('Missing API key, returning mock nonce response');
      return res.json({
        data: {
          nonce: "mock_nonce_" + Date.now(),
          randomness: crypto.randomBytes(16).toString('hex'),
          epoch: 5,
          maxEpoch: 7,
          estimatedExpiration: Date.now() + 3600000 // 1 hour from now
        },
        isFallback: true
      });
    }
    
    try {
      const enokiAxios = createEnokiAxiosInstance();
      
      // Make request with correct parameters according to the documentation
      const response = await retryableRequest(async () => {
        return await enokiAxios.post('/v1/zklogin/nonce', {
          network,
          ephemeralPublicKey,
          additionalEpochs
        });
      });
      
      logger.info('Successfully retrieved zkLogin nonce', response.data);
      res.json(response.data);
    } catch (apiError) {
      logger.error('Failed to get zkLogin nonce from Enoki', {
        message: apiError.message,
        response: apiError.response?.data
      });
      
      // Fallback to a mock nonce
      res.json({
        data: {
          nonce: "mock_nonce_" + Date.now(),
          randomness: crypto.randomBytes(16).toString('hex'),
          epoch: 5,
          maxEpoch: 7,
          estimatedExpiration: Date.now() + 3600000 // 1 hour from now
        },
        isFallback: true
      });
    }
  } catch (error) {
    logger.error('Unexpected error getting nonce', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create ZKP (Zero-Knowledge Proof) from JWT
app.post('/api/enoki/create-zkp', async (req, res) => {
  try {
    const { 
      jwtToken, 
      ephemeralPublicKey, 
      maxEpoch, 
      randomness, 
      network = NETWORK 
    } = req.body;
    
    if (!jwtToken || !ephemeralPublicKey || !maxEpoch || !randomness) {
      return res.status(400).json({
        error: 'Missing required parameters',
        requiredFields: ['jwtToken', 'ephemeralPublicKey', 'maxEpoch', 'randomness']
      });
    }
    
    logger.info('Creating ZKP for zkLogin', {
      keyLength: ephemeralPublicKey.length,
      jwtLength: jwtToken.length,
      network
    });
    
    if (!ENOKI_SECRET_KEY) {
      logger.warn('Missing API key, returning mock ZKP response');
      return res.json({
        data: {
          proofPoints: null,
          issBase64Details: null,
          headerBase64: null,
          addressSeed: crypto.randomBytes(16).toString('hex')
        },
        isFallback: true
      });
    }
    
    try {
      const enokiAxios = createEnokiAxiosInstance(null, {
        'zklogin-jwt': jwtToken
      });
      
      // Create ZKP with proper parameters
      const response = await retryableRequest(async () => {
        return await enokiAxios.post('/v1/zklogin/zkp', {
          network,
          ephemeralPublicKey,
          maxEpoch,
          randomness
        });
      });
      
      logger.info('Successfully created ZKP');
      res.json(response.data);
    } catch (apiError) {
      logger.error('Failed to create ZKP', {
        status: apiError.response?.status,
        data: apiError.response?.data
      });
      
      // Fallback response
      res.json({
        data: {
          proofPoints: null,
          issBase64Details: null,
          headerBase64: null,
          addressSeed: crypto.randomBytes(16).toString('hex')
        },
        isFallback: true
      });
    }
  } catch (error) {
    logger.error('Unexpected error creating ZKP', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get user address from JWT
app.get('/api/enoki/address', async (req, res) => {
  try {
    const jwtToken = req.headers['zklogin-jwt'];
    
    if (!jwtToken) {
      return res.status(400).json({ error: 'Missing zklogin-jwt header' });
    }
    
    logger.info('Getting user address from JWT');
    
    // Check if we're using fallback mode
    if (!ENOKI_SECRET_KEY) {
      // Generate deterministic address from JWT with FIXED LENGTH
      const hash = crypto.createHash('sha256').update(jwtToken.toString()).digest('hex');
      
      const address = '0x' + hash.substring(0, 64); // FIXED: Now using 64 hex chars
      const salt = hash.substring(64, 80); // Adjusted salt start position
      
      logger.warn('Missing API key, returning mock address response');
      return res.json({
        data: {
          salt: salt,
          address: address,
          publicKey: hash.substring(80, 112) // Adjusted publicKey start position
        },
        isFallback: true
      });
    }
    
    try {
      const enokiAxios = createEnokiAxiosInstance(null, {
        'zklogin-jwt': jwtToken
      });
      
      // Get address from JWT
      const response = await retryableRequest(async () => {
        return await enokiAxios.get('/v1/zklogin');
      });
      
      // Validate the address format
      const address = response.data.data.address;
      if (!isValidSuiAddress(address)) {
        logger.warn('Received invalid address format from Enoki API:', address);
        
        // Generate a valid address as fallback
        const hash = crypto.createHash('sha256').update(jwtToken.toString()).digest('hex');
        const validAddress = '0x' + hash.substring(0, 64);
        
        logger.info('Generated valid address as fallback:', validAddress);
        
        // Return a modified response with the valid address
        const modifiedResponse = {
          data: {
            ...response.data.data,
            address: validAddress,
            invalidOriginalAddress: address
          },
          addressValidation: {
            originalValid: false,
            fixedAddress: validAddress
          }
        };
        
        // Cache the fixed address with the JWT for later use
        cacheSessionInfo(jwtToken, {
          address: validAddress,
          salt: response.data.data.salt,
          publicKey: response.data.data.publicKey,
          invalidOriginalAddress: address
        });
        
        res.json(modifiedResponse);
      } else {
        logger.info('Successfully retrieved valid user address', {
          address: address
        });
        
        // Cache the address with the JWT for later use
        cacheSessionInfo(jwtToken, {
          address: response.data.data.address,
          salt: response.data.data.salt,
          publicKey: response.data.data.publicKey
        });
        
        res.json(response.data);
      }
    } catch (apiError) {
      logger.error('Failed to get user address', {
        status: apiError.response?.status,
        data: apiError.response?.data
      });
      
      // Generate deterministic address from JWT with FIXED LENGTH
      const hash = crypto.createHash('sha256').update(jwtToken.toString()).digest('hex');
      
      const address = '0x' + hash.substring(0, 64); // FIXED: Now using 64 hex chars
      const salt = hash.substring(64, 80); // Adjusted salt start position
      
      // Fallback response
      const fallbackData = {
        data: {
          salt: salt,
          address: address,
          publicKey: hash.substring(80, 112) // Adjusted publicKey start position
        },
        isFallback: true
      };
      
      // Cache the fallback address
      cacheSessionInfo(jwtToken, {
        address: fallbackData.data.address,
        salt: fallbackData.data.salt,
        publicKey: fallbackData.data.publicKey,
        isFallback: true
      });
      
      res.json(fallbackData);
    }
  } catch (error) {
    logger.error('Unexpected error getting address', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to create a session
app.post('/api/enoki/create-session', async (req, res) => {
  try {
    const { googleToken, redirectUri } = req.body;
    
    if (!googleToken) {
      logger.warn('Missing googleToken in request body');
      return res.status(400).json({ error: 'Missing googleToken in request body' });
    }
    
    logger.info('Creating Enoki session with Google token', { 
      tokenLength: googleToken.length,
      redirectUri: redirectUri || 'not provided'
    });
    
    if (!ENOKI_SECRET_KEY) {
      logger.warn('Missing API key, using fallback wallet implementation');
      
      try {
        // Get the user info from Google
        const userInfoResponse = await axios.get('https://www.googleapis.com/userinfo/v2/me', {
          headers: { Authorization: `Bearer ${googleToken}` }
        });
        
        const googleUserInfo = userInfoResponse.data;
        logger.info('Successfully retrieved Google user info', { 
          name: googleUserInfo.name,
          email: googleUserInfo.email
        });
        
        // Generate a deterministic wallet based on the user ID for consistency
        const fallbackWallet = generateDeterministicWallet(googleUserInfo.id);
        
        // Validate address format
        if (!isValidSuiAddress(fallbackWallet.userAddress)) {
          logger.error('Generated invalid address format:', fallbackWallet.userAddress);
          return res.status(500).json({ 
            error: 'Generated invalid wallet address',
            details: 'The server generated an invalid Sui address format'
          });
        }
        
        return res.json({
          sessionToken: googleToken, // Use the Google token as the session token
          keypairId: fallbackWallet.keypairId,
          userAddress: fallbackWallet.userAddress,
          name: googleUserInfo.name,
          email: googleUserInfo.email,
          photo: googleUserInfo.picture,
          salt: fallbackWallet.salt,
          isFallback: true
        });
      } catch (googleError) {
        logger.error('Failed to get user info from Google', { 
          message: googleError.message
        });
        
        // If Google verification fails, fall back to a random wallet
        const fallbackWallet = generateDeterministicWallet(googleToken.substring(0, 20));
        
        // Validate address format
        if (!isValidSuiAddress(fallbackWallet.userAddress)) {
          logger.error('Generated invalid address format:', fallbackWallet.userAddress);
          return res.status(500).json({ 
            error: 'Generated invalid wallet address',
            details: 'The server generated an invalid Sui address format'
          });
        }
        
        return res.json({
          sessionToken: "fallback_session_" + Date.now(),
          keypairId: fallbackWallet.keypairId,
          userAddress: fallbackWallet.userAddress,
          salt: fallbackWallet.salt,
          isFallback: true
        });
      }
    }
    
    // In a real implementation, you would:
    // 1. Exchange the Google token for a proper JWT
    // 2. Use that JWT in the 'zklogin-jwt' header to call Enoki's /v1/zklogin endpoint
    // 3. Return the address information
    
    try {
      // Get the user info from Google
      const userInfoResponse = await axios.get('https://www.googleapis.com/userinfo/v2/me', {
        headers: { Authorization: `Bearer ${googleToken}` }
      });
      
      const googleUserInfo = userInfoResponse.data;
      logger.info('Successfully retrieved Google user info for zkLogin', { 
        name: googleUserInfo.name
      });
      
      // In a real implementation, we would:
      // 1. Set up an OAuth redirect with the Enoki nonce
      // 2. Exchange the OAuth code for a JWT
      // 3. Use that JWT with Enoki
      
      // For now, we'll simulate this by:
      // 1. Generate a deterministic "mock JWT" from the Google token
      const mockJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." + 
                      Buffer.from(JSON.stringify({
                        sub: googleUserInfo.id,
                        email: googleUserInfo.email,
                        name: googleUserInfo.name,
                        exp: Math.floor(Date.now() / 1000) + 3600
                      })).toString('base64') + 
                      ".mock-signature";
      
      // 2. Try to get the address using the mock JWT
      const enokiAxios = createEnokiAxiosInstance(null, {
        'zklogin-jwt': mockJwt
      });
      
      let address, salt, publicKey;
      try {
        // Try to get address from Enoki
        const addressResponse = await enokiAxios.get('/v1/zklogin');
        address = addressResponse.data.data.address;
        salt = addressResponse.data.data.salt;
        publicKey = addressResponse.data.data.publicKey;
        
        logger.info('Successfully retrieved zkLogin address from Enoki', {
          address
        });
        
        // Validate the address format
        if (!isValidSuiAddress(address)) {
          logger.warn('Received invalid address format from Enoki API:', address);
          
          // Generate a valid address as fallback
          const hash = crypto.createHash('sha256').update(googleUserInfo.id).digest('hex');
          address = '0x' + hash.substring(0, 64);
          
          logger.info('Generated valid address as fallback:', address);
        }
      } catch (addressError) {
        logger.error('Failed to get zkLogin address, using deterministic fallback', {
          error: addressError.message
        });
        
        // Generate deterministic address from user ID
        const fallbackWallet = generateDeterministicWallet(googleUserInfo.id);
        address = fallbackWallet.userAddress;
        salt = fallbackWallet.salt;
        publicKey = fallbackWallet.keypairId;
      }
      
      // Cache the JWT and address for future use
      cacheSessionInfo(mockJwt, {
        address,
        salt,
        publicKey,
        googleId: googleUserInfo.id,
        name: googleUserInfo.name,
        email: googleUserInfo.email
      });
      
      // Return session info
      return res.json({
        sessionToken: mockJwt,
        keypairId: publicKey,
        userAddress: address,
        name: googleUserInfo.name,
        email: googleUserInfo.email,
        photo: googleUserInfo.picture,
        salt,
        isFallback: false
      });
    } catch (err) {
      logger.error('Error creating session', { error: err.message });
      
      // Fall back to a deterministic wallet if all else fails
      const fallbackWallet = generateDeterministicWallet(googleToken.substring(0, 20));
      
      // Validate address format
      if (!isValidSuiAddress(fallbackWallet.userAddress)) {
        logger.error('Generated invalid address format:', fallbackWallet.userAddress);
        return res.status(500).json({ 
          error: 'Generated invalid wallet address',
          details: 'The server generated an invalid Sui address format'
        });
      }
      
      return res.json({
        sessionToken: "fallback_session_" + Date.now(),
        keypairId: fallbackWallet.keypairId,
        userAddress: fallbackWallet.userAddress,
        salt: fallbackWallet.salt,
        isFallback: true
      });
    }
  } catch (error) {
    logger.error('Unexpected error in create-session', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get user wallet info
app.post('/api/enoki/user-info', async (req, res) => {
  try {
    const { sessionToken } = req.body;
    
    if (!sessionToken) {
      logger.warn('Missing sessionToken in request body');
      return res.status(400).json({ error: 'Missing sessionToken in request body' });
    }
    
    logger.info('Getting user info from session token');
    
    // Check if this is a fallback session
    if (sessionToken.startsWith('fallback_session_')) {
      // For fallback sessions, we need to regenerate the wallet
      // In a real implementation, you'd store and retrieve this from a database
      const seed = sessionToken.substring(sessionToken.lastIndexOf('_') + 1);
      const fallbackWallet = generateDeterministicWallet(seed);
      
      // Validate address format
      if (!isValidSuiAddress(fallbackWallet.userAddress)) {
        logger.error('Generated invalid address format:', fallbackWallet.userAddress);
        return res.status(500).json({ 
          error: 'Generated invalid wallet address',
          details: 'The server generated an invalid Sui address format'
        });
      }
      
      return res.json({
        userAddress: fallbackWallet.userAddress,
        keypairId: fallbackWallet.keypairId,
        salt: fallbackWallet.salt,
        isFallback: true
      });
    }
    
    // Check if we have a cached session
    const cachedSession = getCachedSessionInfo(sessionToken);
    if (cachedSession) {
      logger.info('Retrieved user info from cache', {
        address: cachedSession.address
      });
      
      // Validate address format
      if (!isValidSuiAddress(cachedSession.address)) {
        logger.warn('Cached address has invalid format:', cachedSession.address);
        
        // Generate a valid address as fallback
        const hash = crypto.createHash('sha256').update(sessionToken).digest('hex');
        const validAddress = '0x' + hash.substring(0, 64);
        
        logger.info('Generated valid replacement address:', validAddress);
        
        // Return with the fixed address
        return res.json({
          userAddress: validAddress,
          keypairId: cachedSession.publicKey,
          salt: cachedSession.salt,
          name: cachedSession.name,
          email: cachedSession.email,
          addressFixed: true,
          originalAddress: cachedSession.address,
          isFallback: cachedSession.isFallback || true
        });
      }
      
      return res.json({
        userAddress: cachedSession.address,
        keypairId: cachedSession.publicKey,
        salt: cachedSession.salt,
        name: cachedSession.name,
        email: cachedSession.email,
        isFallback: cachedSession.isFallback || false
      });
    }
    
    // Is this a JWT format token?
    const isJwt = sessionToken.split('.').length === 3;
    
    if (isJwt && ENOKI_SECRET_KEY) {
      try {
        // Try to get address from Enoki
        const enokiAxios = createEnokiAxiosInstance(null, {
          'zklogin-jwt': sessionToken
        });
        
        const addressResponse = await enokiAxios.get('/v1/zklogin');
        const address = addressResponse.data.data.address;
        const salt = addressResponse.data.data.salt;
        const publicKey = addressResponse.data.data.publicKey;
        
        logger.info('Successfully retrieved zkLogin address from token', {
          address
        });
        
        // Validate the address format
        if (!isValidSuiAddress(address)) {
          logger.warn('Received invalid address format from Enoki API:', address);
          
          // Generate a valid address as fallback
          const hash = crypto.createHash('sha256').update(sessionToken).digest('hex');
          const validAddress = '0x' + hash.substring(0, 64);
          
          logger.info('Generated valid address as fallback:', validAddress);
          
          // Cache for future use
          cacheSessionInfo(sessionToken, {
            address: validAddress,
            salt,
            publicKey,
            invalidOriginalAddress: address
          });
          
          return res.json({
            userAddress: validAddress,
            keypairId: publicKey,
            salt,
            addressFixed: true,
            originalAddress: address,
            isFallback: true
          });
        }
        
        // Cache for future use
        cacheSessionInfo(sessionToken, {
          address,
          salt,
          publicKey
        });
        
        return res.json({
          userAddress: address,
          keypairId: publicKey,
          salt,
          isFallback: false
        });
      } catch (addressError) {
        logger.error('Failed to get zkLogin address from token', {
          error: addressError.message
        });
      }
    }
    
    // If everything else fails, generate a fallback wallet
    const fallbackWallet = generateDeterministicWallet(sessionToken);
    
    // Validate address format
    if (!isValidSuiAddress(fallbackWallet.userAddress)) {
      logger.error('Generated invalid address format:', fallbackWallet.userAddress);
      return res.status(500).json({ 
        error: 'Generated invalid wallet address',
        details: 'The server generated an invalid Sui address format'
      });
    }
    
    res.json({
      userAddress: fallbackWallet.userAddress,
      keypairId: fallbackWallet.keypairId,
      salt: fallbackWallet.salt,
      isFallback: true
    });
  } catch (error) {
    logger.error('Unexpected error in user-info endpoint', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================
// SUI TRANSACTION HANDLING
// =============================================

// Create and sponsor a transaction (Enhanced logging version)
app.post('/api/enoki/sponsored-transaction', async (req, res) => {
  try {
    const { 
      sessionToken, 
      operation, 
      params = {} 
    } = req.body;
    
    if (!sessionToken) {
      logger.error('Missing session token in transaction request');
      return res.status(400).json({ error: 'Missing session token' });
    }
    
    if (!operation) {
      logger.error('Missing operation in transaction request');
      return res.status(400).json({ error: 'Missing operation' });
    }
    
    logger.info('Creating sponsored transaction', { 
      operation,
      paramsKeys: Object.keys(params),
      params: JSON.stringify(params)
    });
    
    // Check if we have a package ID
    if (!PACKAGE_ID) {
      logger.error('Missing PACKAGE_ID environment variable');
      return res.status(500).json({
        error: 'Server configuration error',
        message: 'Package ID not configured'
      });
    }
    
    // Get user info from session
    let userInfo;
    const cachedSession = getCachedSessionInfo(sessionToken);
    
    if (cachedSession) {
      userInfo = cachedSession;
      logger.info('Using cached session info for user', {
        userAddress: userInfo.address 
      });
    } else if (sessionToken.startsWith('fallback_session_')) {
      // For fallback sessions, regenerate the wallet
      const seed = sessionToken.substring(sessionToken.lastIndexOf('_') + 1);
      userInfo = generateDeterministicWallet(seed);
      logger.info('Generated fallback wallet for session', {
        seed: seed.substring(0, 5) + '...',
        userAddress: userInfo.address
      });
    } else {
      logger.info('Retrieving user info from Enoki API with token', {
        tokenLength: sessionToken?.length || 0,
        tokenStart: sessionToken ? sessionToken.substring(0, 10) + '...' : null
      });
      
      try {
        // Try to get address from Enoki
        const enokiAxios = createEnokiAxiosInstance(null, {
          'zklogin-jwt': sessionToken
        });
        
        logger.info('Making request to Enoki zkLogin endpoint');
        
        const addressResponse = await enokiAxios.get('/v1/zklogin');
        logger.info('Successfully received Enoki response', {
          status: addressResponse.status,
          dataKeys: Object.keys(addressResponse.data || {})
        });
        
        userInfo = {
          address: addressResponse.data.data.address,
          salt: addressResponse.data.data.salt,
          publicKey: addressResponse.data.data.publicKey
        };
        
        logger.info('Extracted user info from response', {
          address: userInfo.address,
          hasPublicKey: !!userInfo.publicKey
        });
        
        // Cache for future use
        cacheSessionInfo(sessionToken, userInfo);
      } catch (addressError) {
        logger.error('Failed to get user info from token', {
          error: addressError.message,
          status: addressError.response?.status || 'unknown',
          data: addressError.response?.data || {},
          stack: addressError.stack
        });
        
        // Generate a fallback wallet
        userInfo = generateDeterministicWallet(sessionToken);
        logger.info('Generated fallback wallet after API error', {
          userAddress: userInfo.address
        });
      }
    }
    
    // Validate user address
    if (!userInfo || !userInfo.address) {
      logger.error('Missing user address after session processing');
      return res.status(400).json({
        error: 'Invalid session',
        message: 'Could not determine user address from session'
      });
    }
    
    // Validate address format
    if (!isValidSuiAddress(userInfo.address)) {
      logger.warn('User has invalid address format', {
        address: userInfo.address, 
        length: userInfo.address.length
      });
      
      // Generate a valid address as fallback
      const hash = crypto.createHash('sha256').update(sessionToken).digest('hex');
      const validAddress = '0x' + hash.substring(0, 64);
      
      logger.info('Generated valid replacement address', {
        originalAddress: userInfo.address,
        newAddress: validAddress
      });
      
      userInfo.address = validAddress;
    }
    
    // In fallback mode or if using a fallback session token, return a simulated transaction
    if (!ENOKI_SECRET_KEY || sessionToken.startsWith('fallback_session_')) {
      logger.info('Using fallback mode for transaction', { 
        isFallback: true,
        reason: !ENOKI_SECRET_KEY ? 'Missing API key' : 'Fallback session'
      });
      
      // Generate a valid transaction digest
      let digestBytes = Buffer.alloc(32);
      crypto.randomFillSync(digestBytes);
      const digestBase = digestBytes.toString('hex');
      
      // Use standard Sui digest format: 0x followed by 64 chars
      const txDigest = '0x' + digestBase;
      
      logger.info('Generated fallback transaction digest', { digest: txDigest });
      
      return res.json({
        success: true,
        transaction: {
          digest: txDigest,
          timestamp: new Date().toISOString()
        },
        isFallback: true
      });
    }
    
    // Create transaction block
    let tx;
    
    // Use custom transaction from middleware if available
    if (req.customTransaction) {
      logger.info('Using custom transaction from middleware');
      tx = req.customTransaction;
    } else {
      // Create a new transaction block
      logger.info('Creating new transaction block for operation', { operation });
      tx = new TransactionBlock();
      
      // Add appropriate move call based on operation
      if (operation === 'counter::create') {
        // Handle counter::create operation
        const value = params.value || 0;
        logger.info('Building counter::create transaction', { value });
        
        tx.moveCall({
          target: `${PACKAGE_ID}::counter::create`,
          arguments: [tx.pure(value)],
        });
      } 
      else if (operation === 'counter::increment') {
        // Handle counter::increment operation
        logger.info('Building counter::increment transaction', { counterId: params.counterId });
        
        tx.moveCall({
          target: `${PACKAGE_ID}::counter::increment`,
          arguments: [
            tx.object(params.counterId),
          ],
        });
      }
      else if (operation === 'counter::set_value') {
        // Handle counter::set_value operation
        const value = params.value || 0;
        logger.info('Building counter::set_value transaction', { 
          counterId: params.counterId,
          value 
        });
        
        tx.moveCall({
          target: `${PACKAGE_ID}::counter::set_value`,
          arguments: [
            tx.object(params.counterId),
            tx.pure(value),
          ],
        });
      }
      else if (operation === 'boar_challenge::init_pool') {
        // Handle boar_challenge::init_pool operation
        const targetExercises = Number(params.targetExercises || 30);
        const durationDays = Number(params.durationDays || 30);
        
        logger.info('Building boar_challenge::init_pool transaction', { 
          targetExercises,
          durationDays
        });
        
        tx.moveCall({
          target: `${PACKAGE_ID}::boar_challenge::init_pool`,
          arguments: [
            tx.pure(targetExercises),  // Target exercises
            tx.pure(durationDays),     // Duration in days
            tx.object('0x6'),          // Clock object
          ],
        });
      }
      else if (operation === 'boar_challenge::join_challenge') {
        // Handle join_challenge operation
        const poolId = params.poolId;
        const amount = params.amount ? BigInt(params.amount) : BigInt(10000000); // Default 0.01 SUI
        
        logger.info('Building boar_challenge::join_challenge transaction', { 
          poolId,
          amount: amount.toString() 
        });
        
        const [coin] = tx.splitCoins(tx.gas, [tx.pure(amount)]);
        
        tx.moveCall({
          target: `${PACKAGE_ID}::boar_challenge::join_challenge`,
          arguments: [
            tx.object(poolId),
            coin,
            tx.object('0x6'),  // Clock
          ],
        });
      }
      else {
        logger.error(`Unsupported operation: ${operation}`);
        return res.status(400).json({
          success: false,
          error: `Unsupported operation: ${operation}`
        });
      }
    }
    
    try {
      // Serialize transaction to bytes
      logger.info('Serializing transaction');
      const txBytes = await tx.build({ client: suiClient });
      const txBase64 = Buffer.from(txBytes).toString('base64');
      
      logger.info(`Transaction serialized successfully, sponsoring with Enoki...`, {
        txBytesLength: txBytes.length,
        txBase64Length: txBase64.length,
        txBase64Prefix: txBase64.substring(0, 20) + '...'
      });
      
      // Send to Enoki for sponsoring
      const enokiAxios = createEnokiAxiosInstance(null, {
        'zklogin-jwt': sessionToken
      });
      
      // Log the request being sent to Enoki in detail
      logger.info('Sending transaction sponsoring request to Enoki', {
        endpoint: '/v1/transaction-blocks/sponsor',
        network: NETWORK,
        txBase64Length: txBase64.length,
        headers: {
          hasJWT: !!sessionToken,
          jwtLength: sessionToken?.length || 0
        }
      });
      
      try {
        // Send the sponsor request
        const sponsorResponse = await enokiAxios.post('/v1/transaction-blocks/sponsor', {
          network: NETWORK, 
          transactionBlockKindBytes: txBase64
        });
        
        logger.info(`Transaction sponsored successfully`, {
          status: sponsorResponse.status,
          statusText: sponsorResponse.statusText,
          digest: sponsorResponse.data.data.digest,
          responseKeys: Object.keys(sponsorResponse.data || {}),
          dataKeys: Object.keys(sponsorResponse.data?.data || {})
        });
        
        // Return the transaction details to the client
        return res.json({
          success: true,
          transaction: {
            digest: sponsorResponse.data.data.digest,
            bytes: sponsorResponse.data.data.bytes,
            timestamp: new Date().toISOString()
          },
          isFallback: false
        });
      } catch (sponsorError) {
        // Log detailed error information for sponsoring failures
        logger.error(`Failed to sponsor transaction:`, {
          message: sponsorError.message,
          status: sponsorError.response?.status,
          statusText: sponsorError.response?.statusText,
          data: sponsorError.response?.data,
          headers: sponsorError.response?.headers,
          config: {
            url: sponsorError.config?.url,
            method: sponsorError.config?.method,
            baseURL: sponsorError.config?.baseURL,
            headers: sponsorError.config?.headers,
            hasData: !!sponsorError.config?.data
          },
          stack: sponsorError.stack
        });
        
        // If this was a real Enoki error with a response
        if (sponsorError.response?.data) {
          return res.status(sponsorError.response.status || 400).json({
            success: false,
            error: 'Failed to sponsor transaction',
            details: sponsorError.response.data,
            message: sponsorError.message
          });
        }
        
        // Generic error handling
        return res.status(500).json({
          success: false,
          error: 'Failed to sponsor transaction',
          details: sponsorError.message,
          stack: sponsorError.stack
        });
      }
    } catch (error) {
      logger.error(`Unexpected error in transaction handler:`, {
        message: error.message,
        stack: error.stack,
        operation
      });
      return res.status(500).json({
        success: false,
        error: 'Internal server error',
        details: error.message,
        stack: error.stack
      });
    }
  } catch (error) {
    logger.error(`Top-level error in sponsored-transaction endpoint:`, {
      message: error.message,
      stack: error.stack
    });
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message,
      stack: error.stack
    });
  }
});

// Execute a sponsored transaction
app.post('/api/enoki/execute-transaction', async (req, res) => {
  try {
    const { digest, signature, bytes } = req.body;
    
    if (!digest) {
      return res.status(400).json({ error: 'Missing transaction digest' });
    }
    
    if (!signature && !digest.startsWith('simulated_tx') && !digest.startsWith('0x')) {
      return res.status(400).json({ error: 'Missing signature' });
    }
    
    logger.info('Executing transaction', { digest });
    
    // If this is a simulated transaction, return success
    if (digest.startsWith('simulated_tx') || (digest.startsWith('0x') && !ENOKI_SECRET_KEY)) {
      logger.info('Executing simulated transaction', { digest });
      
      return res.json({
        success: true,
        transaction: {
          digest,
          status: 'success',
          timestamp: new Date().toISOString()
        },
        isFallback: true
      });
    }
    
    // If Enoki is not available, fall back to simulation
    if (!ENOKI_SECRET_KEY) {
      logger.warn('Enoki API key not available, returning simulated execution');
      
      return res.json({
        success: true,
        transaction: {
          digest,
          status: 'success',
          timestamp: new Date().toISOString()
        },
        isFallback: true
      });
    }
    
    try {
      const enokiAxios = createEnokiAxiosInstance();
      
      // Execute the transaction
      const executeResponse = await enokiAxios.post(
        `/v1/transaction-blocks/sponsor/${digest}`,
        { signature }
      );
      
      logger.info('Transaction executed successfully', {
        digest: executeResponse.data.data.digest
      });
      
      return res.json({
        success: true,
        transaction: {
          digest: executeResponse.data.data.digest,
          status: 'success',
          timestamp: new Date().toISOString()
        },
        isFallback: false
      });
    } catch (executeError) {
      logger.error('Failed to execute transaction', {
        error: executeError.message,
        response: executeError.response?.data
      });
      
      // Return a simulated result if execution fails
      return res.json({
        success: false,
        transaction: {
          digest,
          status: 'failed',
          error: executeError.message,
          errorResponse: executeError.response?.data,
          timestamp: new Date().toISOString()
        },
        isFallback: true
      });
    }
  } catch (error) {
    logger.error('Unexpected error executing transaction', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get transaction status
app.get('/api/enoki/transaction/:digest', async (req, res) => {
  try {
    const { digest } = req.params;
    
    if (!digest) {
      return res.status(400).json({
        success: false,
        error: 'Transaction digest is required'
      });
    }
    
    // Validate digest format
    if (!digest.startsWith('0x') && !digest.startsWith('simulated_tx')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid transaction digest format'
      });
    }
    
    // Check if it's a simulated transaction
    if (digest.startsWith('simulated_tx')) {
      return res.json({
        success: true,
        status: 'success',
        isFallback: true
      });
    }
    
    // Query Sui for transaction status
    try {
      const txResult = await suiClient.getTransactionBlock({
        digest,
        options: {
          showEffects: true,
          showEvents: true
        }
      });
      
      return res.json({
        success: true,
        status: txResult.effects?.status?.status || 'unknown',
        timestamp: txResult.timestampMs ? new Date(parseInt(txResult.timestampMs)).toISOString() : null,
        transaction: txResult,
        isFallback: false
      });
    } catch (txError) {
      logger.error(`Failed to get transaction:`, txError);
      
      return res.status(404).json({
        success: false,
        error: 'Transaction not found',
        details: txError.message
      });
    }
  } catch (error) {
    logger.error(`Unexpected error getting transaction:`, error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      details: error.message
    });
  }
});

// Endpoint to fix invalid addresses
app.post('/api/fix-address', async (req, res) => {
  try {
    const { address } = req.body;
    
    if (!address) {
      return res.status(400).json({ 
        success: false,
        error: 'Address is required' 
      });
    }
    
    // Check if the address is already valid
    if (isValidSuiAddress(address)) {
      return res.json({
        success: true,
        address: address,
        fixed: false,
        message: 'Address is already valid'
      });
    }
    
    // Generate a valid address
    const hash = crypto.createHash('sha256').update(address).digest('hex');
    const fixedAddress = '0x' + hash.substring(0, 64);
    
    logger.info('Fixed invalid address', {
      original: address,
      fixed: fixedAddress
    });
    
    return res.json({
      success: true,
      originalAddress: address,
      fixedAddress: fixedAddress,
      fixed: true,
      isValid: isValidSuiAddress(fixedAddress)
    });
  } catch (error) {
    logger.error('Error fixing address', { error: error.message });
    return res.status(500).json({
      success: false,
      error: 'Failed to fix address'
    });
  }
});

// =============================================
// TESTING AND DEBUGGING ENDPOINTS
// =============================================

// Comprehensive Enoki API debug endpoint
app.get('/api/enoki/debug', async (req, res) => {
  try {
    logger.info('Running Enoki API diagnostics');
    
    const results = {
      timestamp: new Date().toISOString(),
      configStatus: {
        hasSecretKey: !!ENOKI_SECRET_KEY,
        secretKeyLength: ENOKI_SECRET_KEY ? ENOKI_SECRET_KEY.length : 0,
        hasPublicKey: !!ENOKI_PUBLIC_KEY,
        publicKeyLength: ENOKI_PUBLIC_KEY ? ENOKI_PUBLIC_KEY.length : 0,
        hasPackageId: !!PACKAGE_ID,
        packageId: PACKAGE_ID
      },
      connectionTests: {},
      enokiBasicInfo: {},
      endpointTests: {},
      versions: {},
      addressGeneration: {
        test1: generateDeterministicWallet('test_seed_1'),
        test2: generateDeterministicWallet('test_seed_2')
      }
    };
    
    // Validate generated addresses
    results.addressGeneration.addressValidation = {
      test1Valid: isValidSuiAddress(results.addressGeneration.test1.userAddress),
      test1Length: results.addressGeneration.test1.userAddress.length,
      test1HexLength: results.addressGeneration.test1.userAddress.startsWith('0x') ? 
        results.addressGeneration.test1.userAddress.length - 2 : null,
      test2Valid: isValidSuiAddress(results.addressGeneration.test2.userAddress),
      test2Length: results.addressGeneration.test2.userAddress.length,
      test2HexLength: results.addressGeneration.test2.userAddress.startsWith('0x') ? 
        results.addressGeneration.test2.userAddress.length - 2 : null,
      expectedFormat: '0x + 64 hex characters (66 chars total)'
    };
    
    // Test basic connectivity - DNS resolution
    try {
      const ipv4 = await new Promise((resolve, reject) => {
        dns.lookup('api.enoki.mystenlabs.com', { family: 4 }, (err, address) => {
          if (err) reject(err);
          else resolve(address);
        });
      });
      
      results.connectionTests.dns = {
        success: true,
        ipv4Address: ipv4
      };
      
      // Test TCP connection to port 443
      const socket = new require('net').Socket();
      
      const tcpConnectResult = await new Promise((resolve) => {
        socket.setTimeout(5000);
        
        socket.on('connect', () => {
          socket.end();
          resolve({
            success: true,
            message: 'Successfully connected to TCP port 443'
          });
        });
        
        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            message: 'TCP connection timeout'
          });
        });
        
        socket.on('error', (err) => {
          resolve({
            success: false,
            message: `TCP connection error: ${err.message}`
          });
        });
        
        socket.connect(443, ipv4);
      });
      
      results.connectionTests.tcp = tcpConnectResult;
    } catch (dnsError) {
      results.connectionTests.dns = {
        success: false,
        error: dnsError.message
      };
    }
    
    // Only test the API if we have a key
    if (ENOKI_SECRET_KEY) {
      const enokiAxios = createEnokiAxiosInstance();
      
      // Test app metadata endpoint
      try {
        const appResponse = await enokiAxios.get('/v1/app');
        
        results.configStatus.keyTest = {
          success: true,
          status: appResponse.status,
          data: appResponse.data
        };
        
        // Store basic info
        results.enokiBasicInfo = {
          allowedOrigins: appResponse.data.data.allowedOrigins || [],
          authProviders: appResponse.data.data.authenticationProviders || [],
          hasGoogleProvider: appResponse.data.data.authenticationProviders?.some(p => p.providerType === 'google') || false
        };
      } catch (keyError) {
        results.configStatus.keyTest = {
          success: false,
          status: keyError.response?.status,
          error: keyError.message,
          data: keyError.response?.data
        };
      }
      
      // Test multiple versions
      const versions = ['v0', 'v1', 'v2', 'v3', 'api/v1'];
      for (const version of versions) {
        try {
          const versionResponse = await axios.get(`${ENOKI_API_URL}/${version}/health`, {
            validateStatus: () => true,
            timeout: 5000
          });
          
          results.versions[version] = {
            status: versionResponse.status,
            statusText: versionResponse.statusText,
            headers: versionResponse.headers,
            data: versionResponse.data
          };
        } catch (versionError) {
          results.versions[version] = {
            success: false,
            error: versionError.message
          };
        }
      }
      
      // Test various endpoints
      const endpoints = [
        { 
          name: 'get_app',
          version: 'v1', 
          path: '/app', 
          method: 'GET' 
        },
        { 
          name: 'zklogin_nonce',
          version: 'v1', 
          path: '/zklogin/nonce', 
          method: 'POST', 
          data: {
            network: NETWORK,
            ephemeralPublicKey: Buffer.from('testPublicKey123456789').toString('base64'),
            additionalEpochs: 2
          }
        },
        { 
          name: 'zklogin',
          version: 'v1', 
          path: '/zklogin', 
          method: 'GET' 
        }
      ];
      
      for (const endpoint of endpoints) {
        try {
          const url = `${ENOKI_API_URL}/${endpoint.version}${endpoint.path}`;
          
          let response;
          if (endpoint.method === 'GET') {
            response = await enokiAxios.get(url, {
              validateStatus: () => true,
              timeout: 5000
            });
          } else {
            response = await enokiAxios.post(url, endpoint.data || {}, {
              validateStatus: () => true,
              timeout: 5000
            });
          }
          
          results.endpointTests[endpoint.name] = {
            url: `${endpoint.version}${endpoint.path}`,
            method: endpoint.method,
            status: response.status,
            statusText: response.statusText,
            data: response.data
          };
        } catch (endpointError) {
          results.endpointTests[endpoint.name] = {
            url: `${endpoint.version}${endpoint.path}`,
            method: endpoint.method,
            success: false,
            error: endpointError.message,
            response: endpointError.response?.data
          };
        }
      }
    } else {
      // Note API key is missing
      results.configStatus.keyTest = {
        success: false,
        error: 'ENOKI_SECRET_KEY not configured'
      };
    }
    
    // Test package ID configuration
    if (PACKAGE_ID) {
      results.configStatus.packageIdTest = {
        success: true,
        packageId: PACKAGE_ID
      };
    } else {
      results.configStatus.packageIdTest = {
        success: false,
        error: 'PACKAGE_ID not configured'
      };
    }
    
    // Generate summary
    const summary = {
      canConnect: results.connectionTests.tcp?.success || false,
      apiKeyValid: results.configStatus.keyTest?.success || false,
      hasPackageId: !!PACKAGE_ID,
      workingEndpoints: [],
      workingVersion: null,
      addressGenerationValid: results.addressGeneration.addressValidation.test1Valid && 
                            results.addressGeneration.addressValidation.test2Valid,
      recommendedAction: ''
    };
    
    // Check for any working endpoints
    if (ENOKI_SECRET_KEY) {
      for (const [name, data] of Object.entries(results.endpointTests)) {
        if (data.status && 
            (data.status === 200 || data.status === 201 || data.status === 204 || 
             data.status === 400 || data.status === 202)) {
          summary.workingEndpoints.push(name);
        }
      }
    }
    
    // Check if any API version has a working health endpoint
    for (const [version, data] of Object.entries(results.versions)) {
      if (data.status && (data.status === 200 || data.status === 204)) {
        summary.workingVersion = version;
        break;
      }
    }
    
    // Generate recommendation
    if (!ENOKI_SECRET_KEY) {
      summary.recommendedAction = 'ENOKI_SECRET_KEY is missing. Add it to your environment variables.';
    } else if (!summary.canConnect) {
      summary.recommendedAction = 'Cannot connect to Enoki API. Check network configuration and firewall settings.';
    } else if (!summary.apiKeyValid) {
      summary.recommendedAction = 'Your Enoki API key appears to be invalid. Generate a new key from the Enoki portal.';
    } else if (!PACKAGE_ID) {
      summary.recommendedAction = 'PACKAGE_ID is not configured. Add it to your environment variables.';
    } else if (!summary.addressGenerationValid) {
      summary.recommendedAction = 'Address generation is producing invalid addresses. Update the generateDeterministicWallet function.';
    } else if (summary.workingVersion) {
      summary.recommendedAction = `Use API version ${summary.workingVersion} for Enoki integration.`;
    } else if (summary.workingEndpoints.length > 0) {
      summary.recommendedAction = `Some endpoints may work - try using these specific endpoints: ${summary.workingEndpoints.join(', ')}`;
    } else {
      summary.recommendedAction = 'No working Enoki API endpoints found. Continue using fallback wallet implementation or contact Mysten Labs for support.';
    }
    
    results.summary = summary;
    
    logger.info('Enoki diagnostics completed', { 
      canConnect: summary.canConnect,
      apiKeyValid: summary.apiKeyValid,
      workingEndpointsCount: summary.workingEndpoints.length,
      addressGenerationValid: summary.addressGenerationValid
    });
    
    res.json(results);
  } catch (error) {
    logger.error('Failed to complete diagnostics', { error: error.message });
    res.status(500).json({ 
      error: 'Failed to complete diagnostics',
      message: error.message,
      stack: error.stack
    });
  }
});

// API key testing endpoint
app.post('/api/enoki/test-key', async (req, res) => {
  try {
    const { apiKey, publicApiKey } = req.body;
    
    if (!apiKey) {
      return res.status(400).json({
        valid: false,
        message: 'API key is required'
      });
    }
    
    logger.info('Testing custom Enoki API key');
    
    // Create an Axios instance with the provided key
    const testAxios = axios.create({
      baseURL: ENOKI_API_URL,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      httpAgent: new http.Agent({ family: 4 }),
      httpsAgent: new https.Agent({ family: 4 }),
      timeout: 10000
    });
    
    const results = {
      valid: false,
      keyDetails: {
        privateKeyLength: apiKey.length,
        publicKeyProvided: !!publicApiKey,
        publicKeyLength: publicApiKey ? publicApiKey.length : 0
      },
      tests: {}
    };
    
    // Try most basic endpoint first - app metadata
    try {
      const appResponse = await testAxios.get('/v1/app');
      
      results.tests.app = {
        success: true,
        status: appResponse.status,
        data: appResponse.data
      };
      
      // If this worked, the key is valid
      results.valid = true;
      results.message = 'API key is valid for app metadata endpoint';
    } catch (appError) {
      results.tests.app = {
        success: false,
        status: appError.response?.status,
        error: appError.message,
        data: appError.response?.data
      };
    }
    
    // Try nonce endpoint with proper parameters
    if (!results.valid) {
      try {
        const ephemeralPublicKey = Buffer.from('testPublicKey123456789').toString('base64');
        
        const nonceResponse = await testAxios.post('/v1/zklogin/nonce', {
          network: NETWORK,
          ephemeralPublicKey: ephemeralPublicKey,
          additionalEpochs: 2
        });
        
        results.tests.nonce = {
          success: true,
          status: nonceResponse.status,
          data: nonceResponse.data
        };
        
        // If this worked, the key is valid
        results.valid = true;
        results.message = 'API key is valid for zklogin/nonce endpoint';
      } catch (nonceError) {
        results.tests.nonce = {
          success: false,
          status: nonceError.response?.status,
          error: nonceError.message,
          data: nonceError.response?.data
        };
      }
    }
    
    // If we still don't have a valid result, check if we got authentication errors
    if (!results.valid) {
      let hasAuthError = false;
      
      for (const test of Object.values(results.tests)) {
        if (test.status === 401 || test.status === 403) {
          hasAuthError = true;
          break;
        }
      }
      
      if (hasAuthError) {
        results.message = 'API key format is valid but authorization failed. Key may be expired or invalid.';
      } else {
        results.message = 'Could not validate API key. All endpoints returned unexpected responses.';
      }
    }
    
    logger.info('API key test completed', { 
      valid: results.valid
    });
    
    res.json(results);
  } catch (error) {
    logger.error('Error testing API key', { error: error.message });
    res.status(500).json({
      valid: false,
      error: 'Failed to test API key',
      message: error.message
    });
  }
});

// Update API keys endpoint
app.post('/api/enoki/update-keys', async (req, res) => {
  try {
    const { secretKey, publicKey } = req.body;
    
    if (!secretKey) {
      return res.status(400).json({
        success: false,
        error: 'Secret API key is required'
      });
    }
    
    logger.info('Updating Enoki API keys');
    
    // Test the new key first
    const testAxios = axios.create({
      baseURL: ENOKI_API_URL,
      headers: {
        'Authorization': `Bearer ${secretKey}`,
        'Content-Type': 'application/json'
      },
      timeout: 10000
    });
    
    let keyValid = false;
    try {
      // Try to get app metadata
      const response = await testAxios.get('/v1/app');
      keyValid = response.status === 200;
    } catch (error) {
      logger.error('Failed to validate new API key', { error: error.message });
      return res.status(400).json({
        success: false,
        error: 'Failed to validate new API key',
        message: 'The provided key could not be validated with the Enoki API'
      });
    }
    
    if (!keyValid) {
      return res.status(400).json({
        success: false,
        error: 'Invalid API key',
        message: 'The provided key is not valid for the Enoki API'
      });
    }
    
    // For a real implementation, store these keys securely
    // For this example, we'll create a .env.new file
    try {
      const newEnvContent = [
        `# Generated by Enoki API key update on ${new Date().toISOString()}`,
        `ENOKI_SECRET_KEY=${secretKey}`,
        publicKey ? `NEXT_PUBLIC_ENOKI_API_KEY=${publicKey}` : '# No public key provided'
      ].join('\n');
      
      const newEnvPath = path.join(__dirname, '.env.new');
      fs.writeFileSync(newEnvPath, newEnvContent);
      
      logger.info('API keys updated and saved to .env.new');
      
      // We can't update the environment variables at runtime,
      // but we can set them for this process (not recommended in production)
      process.env.ENOKI_SECRET_KEY = secretKey;
      if (publicKey) {
        process.env.NEXT_PUBLIC_ENOKI_API_KEY = publicKey;
      }
      
      return res.json({
        success: true,
        message: 'API keys updated successfully. Restart the server to apply the changes.',
        note: 'The new keys have been saved to .env.new and set for this process.'
      });
    } catch (error) {
      logger.error('Failed to save new API keys', { error: error.message });
      return res.status(500).json({
        success: false,
        error: 'Failed to save new API keys',
        message: error.message
      });
    }
  } catch (error) {
    logger.error('Unexpected error updating API keys', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// =============================================
// SERVER STARTUP
// =============================================

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, '0.0.0.0', () => {
  logger.info(`Server running on port ${PORT}`);
  logger.info(`Server is accessible at http://localhost:${PORT} or on your local network`);
  logger.info(`Health check: http://localhost:${PORT}/api/health`);
  logger.info(`Enoki status: http://localhost:${PORT}/api/enoki/status`);
  
  // Validate address generation
  const testWallet = generateDeterministicWallet('test_seed');
  const isValid = isValidSuiAddress(testWallet.userAddress);
  
  logger.info('Address generation test:', {
    address: testWallet.userAddress,
    isValid: isValid,
    length: testWallet.userAddress.length,
    hexLength: testWallet.userAddress.startsWith('0x') ? testWallet.userAddress.length - 2 : null
  });
  
  if (!isValid) {
    logger.error('WARNING: Address generation is producing invalid Sui addresses!');
  }
  
  // Log config status
  logger.info('Server configuration:', {
    hasSecretKey: !!ENOKI_SECRET_KEY,
    hasPublicKey: !!ENOKI_PUBLIC_KEY,
    hasPackageId: !!PACKAGE_ID,
    network: NETWORK,
    port: PORT,
    addressGenerationValid: isValid
  });
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  logger.info('Server shutting down');
  logStream.end();
  process.exit(0);
});
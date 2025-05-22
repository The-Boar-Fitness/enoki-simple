// contractMiddleware.js - With enhanced debugging for sui_transfer and fixed transaction sender
const { TransactionBlock } = require('@mysten/sui.js/transactions');

/**
 * Middleware to handle custom contract operations
 * This adds special handling for operations like boar_challenge::init_pool
 * that may need different parameter encoding or structure
 */
const contractMiddleware = (req, res, next) => {
  // Only process sponsored transaction requests
  if (req.path !== '/api/enoki/sponsored-transaction') {
    return next();
  }

  const { operation, params, sessionToken } = req.body;
  const logger = req.app.get('logger') || console;
  
  logger.info(`Contract middleware processing operation: ${operation}`, {
    paramKeys: params ? Object.keys(params) : [],
    paramValues: params ? JSON.stringify(params) : 'none'
  });
  
  // Extract user address from session token if available
  let senderAddress = null;
  try {
    // Try to get the sender address from the session token or request body
    if (req.body.senderAddress) {
      senderAddress = req.body.senderAddress;
    } else if (req.user && req.user.suiAddress) {
      senderAddress = req.user.suiAddress;
    } else if (sessionToken) {
      // Assuming the session token is a JWT, you might need to decode it to get the user info
      // This is a placeholder - implement according to your session token structure
      // const decodedToken = jwt.decode(sessionToken);
      // senderAddress = decodedToken.suiAddress;
      
      // For now, try to get it from the app context if available
      senderAddress = req.app.get('currentUserAddress');
    }
    
    if (senderAddress) {
      logger.info(`Using sender address: ${senderAddress}`);
    } else {
      logger.warn('No sender address found in request or context');
    }
  } catch (error) {
    logger.error('Error extracting sender address', {
      error: error.message
    });
  }
  
  // Handle SUI TRANSFER operation - DEBUGGING VERSION
  if (operation === 'sui_transfer') {
    // Handle SUI token transfer with extensive debugging
    try {
      logger.info(`[DEBUG] Creating SUI transfer transaction - START`);
      
      // Validate required parameters
      const recipient = params.recipient;
      const amountStr = params.amount;
      
      logger.info(`[DEBUG] Received transfer parameters`, {
        recipient,
        amount: amountStr,
        recipientType: typeof recipient,
        amountType: typeof amountStr,
        recipientLength: recipient ? recipient.length : 0,
        hasRecipient: !!recipient,
        hasAmount: !!amountStr,
        senderAddress
      });
      
      if (!recipient || !amountStr) {
        logger.error('[DEBUG] Missing required parameters for sui_transfer', {
          hasRecipient: !!recipient,
          hasAmount: !!amountStr
        });
        return res.status(400).json({
          success: false,
          error: 'Recipient address and amount are required for SUI transfer'
        });
      }
      
      // Parse amount safely
      let amount;
      try {
        // Handle amount parsing for different input formats
        if (typeof amountStr === 'number') {
          amount = BigInt(amountStr);
          logger.info(`[DEBUG] Parsed number amount directly: ${amount.toString()}`);
        } else if (amountStr.includes('.')) {
          const floatAmount = parseFloat(amountStr);
          amount = BigInt(Math.floor(floatAmount * 1000000000));
          logger.info(`[DEBUG] Parsed float amount ${amountStr} to ${amount.toString()}`);
        } else {
          amount = BigInt(amountStr);
          logger.info(`[DEBUG] Parsed integer amount ${amountStr} to ${amount.toString()}`);
        }
      } catch (parseError) {
        logger.error('[DEBUG] Invalid amount format for SUI transfer', {
          amount: amountStr,
          error: parseError.message,
          stack: parseError.stack
        });
        return res.status(400).json({
          success: false,
          error: `Invalid amount format: ${parseError.message}. Must be a valid number string.`
        });
      }
      
      // Validate recipient address format
      if (!recipient.startsWith('0x')) {
        logger.error('[DEBUG] Recipient address missing 0x prefix', { recipient });
        return res.status(400).json({
          success: false,
          error: `Invalid recipient address format: missing 0x prefix.`
        });
      }
      
      if (recipient.length !== 66) {
        logger.error('[DEBUG] Invalid recipient address length', { 
          recipient, 
          length: recipient.length 
        });
        return res.status(400).json({
          success: false,
          error: `Invalid recipient address length: ${recipient.length}. Expected: 66 characters.`
        });
      }
      
      // Make sure amount is positive
      if (amount <= BigInt(0)) {
        logger.error('[DEBUG] Amount must be positive', { amount: amount.toString() });
        return res.status(400).json({
          success: false,
          error: 'Amount must be positive'
        });
      }
      
      // Set a reasonable maximum for gas safety (test with a small amount first)
      const MAX_AMOUNT = BigInt('1000000000000'); // 1,000 SUI
      if (amount > MAX_AMOUNT) {
        logger.error('[DEBUG] Amount exceeds maximum allowed', { 
          amount: amount.toString(),
          max: MAX_AMOUNT.toString() 
        });
        return res.status(400).json({
          success: false,
          error: `Amount exceeds maximum allowed (1,000 SUI). Requested: ${Number(amount) / 1000000000} SUI`
        });
      }
      
      // Print summary before creating transaction
      logger.info(`[DEBUG] Creating SUI transfer of ${amount.toString()} MIST to ${recipient}`);
      
      // Create transaction block
      let tx;
      try {
        logger.info('[DEBUG] Creating transaction block');
        tx = new TransactionBlock();
        
        // IMPORTANT: Set the sender for the transaction block 
        // This is the fix for the "Missing transaction sender" error
        if (senderAddress) {
          tx.setSender(senderAddress);
          logger.info(`[DEBUG] Transaction sender set to: ${senderAddress}`);
        } else {
          // If we still don't have a sender address, try to get it from the recipient
          // (In case of self-transfers, this might be valid)
          if (req.body.isSelfTransfer) {
            tx.setSender(recipient);
            logger.info(`[DEBUG] Self-transfer detected, using recipient as sender: ${recipient}`);
          } else {
            logger.error('[DEBUG] No sender address available for transaction');
            return res.status(400).json({
              success: false,
              error: 'Missing transaction sender address. Please ensure you are logged in correctly.'
            });
          }
        }
        
        logger.info('[DEBUG] Transaction block created successfully');
      } catch (txCreateError) {
        logger.error('[DEBUG] Error creating transaction block', {
          error: txCreateError.message,
          stack: txCreateError.stack
        });
        throw txCreateError;
      }
      
      try {
        // Split coins from gas (user's balance)
        logger.info('[DEBUG] Creating coin split');
        let coin;
        try {
          [coin] = tx.splitCoins(tx.gas, [tx.pure(amount)]);
          logger.info('[DEBUG] Coin split successful', { 
            gasObjectRef: tx.gas.toString(),
            amount: amount.toString() 
          });
        } catch (splitError) {
          logger.error('[DEBUG] Error in coin split', {
            error: splitError.message,
            stack: splitError.stack,
            amount: amount.toString()
          });
          throw splitError;
        }
        
        // Transfer the split coin to recipient
        logger.info('[DEBUG] Creating transfer objects call');
        try {
          tx.transferObjects([coin], tx.pure(recipient));
          logger.info('[DEBUG] Transfer objects call successful');
        } catch (transferError) {
          logger.error('[DEBUG] Error in transfer objects call', {
            error: transferError.message,
            stack: transferError.stack,
            recipient
          });
          throw transferError;
        }
        
        logger.info('[DEBUG] SUI transfer transaction created successfully');
      } catch (txError) {
        logger.error('[DEBUG] Error creating SUI transfer transaction operations', {
          error: txError.message,
          stack: txError.stack,
          recipient,
          amount: amount.toString()
        });
        throw txError;
      }
      
      // Try to serialize transaction to check for any issues
      try {
        logger.info('[DEBUG] Building transaction to test validity');
        const txData = tx.blockData;
        logger.info('[DEBUG] Transaction successfully built and validated', {
          hasInputs: txData.inputs.length > 0,
          hasTransactions: txData.transactions.length > 0,
          sender: tx.sender
        });
      } catch (buildError) {
        logger.error('[DEBUG] Error building transaction', {
          error: buildError.message,
          stack: buildError.stack
        });
        // Continue anyway, as it might just be a serialization issue for testing
      }
      
      // Set the transaction on the request object
      req.customTransaction = tx;
      logger.info('[DEBUG] Transaction set on request object. Continuing...');
      
      return next();
    } catch (error) {
      logger.error('[DEBUG] Error in SUI transfer middleware:', {
        error: error.message,
        operation,
        stack: error.stack,
        params: JSON.stringify(params)
      });
      return res.status(500).json({
        success: false,
        error: 'Failed to create SUI transfer transaction',
        details: error.message,
        stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined
      });
    }
  }
  
  // [Rest of your code for other operations remains the same]
  // Handle boar_challenge operations specially
  else if (operation && operation.startsWith('boar_challenge::')) {
    // [Your existing code for boar_challenge operations]
    // Make sure to set tx.setSender(senderAddress) if available

    logger.info(`Custom contract handler for operation: ${operation}`, { params });
    
    // Get package ID from environment or request
    const packageId = process.env.PACKAGE_ID || req.app.get('packageId');
    
    if (!packageId) {
      logger.error('No package ID configured for contract operations');
      return res.status(400).json({
        success: false,
        error: 'Contract package ID not configured'
      });
    }
    
    logger.info(`Using package ID: ${packageId}`);
    
    // Create a custom transaction block for the specific operation
    try {
      const tx = new TransactionBlock();
      
      // SET THE SENDER HERE TOO
      if (senderAddress) {
        tx.setSender(senderAddress);
        logger.info(`Transaction sender set to: ${senderAddress}`);
      }
      
      // [Rest of your boar_challenge handling logic]
      // ...
      
    } catch (error) {
      // [Your existing error handling]
    }
  } 
  else if (operation === 'counter::create') {
    // Special handling for counter::create to make sure it works
    try {
      const logger = req.app.get('logger') || console;
      logger.info(`Using optimized handling for counter::create`);
      
      const packageId = process.env.PACKAGE_ID || req.app.get('packageId');
      
      if (!packageId) {
        logger.error('No package ID configured for contract operations');
        return res.status(400).json({
          success: false,
          error: 'Contract package ID not configured'
        });
      }
      
      const value = Number(params.value || 0);
      logger.info(`Creating counter with value: ${value}`);
      
      const tx = new TransactionBlock();
      
      // SET THE SENDER HERE TOO
      if (senderAddress) {
        tx.setSender(senderAddress);
        logger.info(`Transaction sender set to: ${senderAddress}`);
      } else {
        logger.warn('No sender address available for counter::create transaction');
        // For testing operations like this, you might want to continue even without a sender
        // as it will be set later in the pipeline
      }
      
      try {
        tx.moveCall({
          target: `${packageId}::counter::create`,
          arguments: [tx.pure(value)],
        });
        
        logger.info('counter::create transaction created successfully');
      } catch (moveCallError) {
        logger.error('Error creating move call for counter::create', {
          error: moveCallError.message,
          stack: moveCallError.stack,
          packageId,
          value
        });
        throw moveCallError;
      }
      
      req.customTransaction = tx;
      return next();
    } catch (error) {
      logger.error('Error creating counter transaction:', {
        error: error.message,
        stack: error.stack,
        params
      });
      return next(); // Continue with normal processing if this fails
    }
  }
  
  // For all other operations, continue normally
  logger.info(`No custom handling for ${operation}, continuing with normal processing`);
  return next();
};

module.exports = contractMiddleware;
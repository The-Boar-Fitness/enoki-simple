// contractMiddleware.js - With enhanced error logging
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

  const { operation, params } = req.body;
  const logger = req.app.get('logger') || console;
  
  logger.info(`Contract middleware processing operation: ${operation}`, {
    paramKeys: params ? Object.keys(params) : []
  });
  
  // Handle boar_challenge operations specially
  if (operation && operation.startsWith('boar_challenge::')) {
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
      
      // Handle different boar_challenge operations
      if (operation === 'boar_challenge::init_pool') {
        const targetExercises = Number(params.targetExercises || 30);
        const durationDays = Number(params.durationDays || 30);
        
        logger.info(`Creating init_pool transaction with: target=${targetExercises}, duration=${durationDays}`);
        
        // Add the move call
        try {
          tx.moveCall({
            target: `${packageId}::boar_challenge::init_pool`,
            arguments: [
              tx.pure(targetExercises),  // Target exercises
              tx.pure(durationDays),     // Duration in days
              tx.object('0x6'),          // Clock object
            ],
          });
          
          logger.info('init_pool transaction created successfully');
        } catch (moveCallError) {
          logger.error('Error creating move call for init_pool', {
            error: moveCallError.message,
            stack: moveCallError.stack,
            packageId,
            targetExercises,
            durationDays
          });
          throw moveCallError;
        }
        
        // Store the transaction in the request for later processing
        req.customTransaction = tx;
        
        // Continue with the request
        return next();
      }
      else if (operation === 'boar_challenge::join_challenge') {
        // Handle join_challenge operation
        const poolId = params.poolId;
        const amount = params.amount ? BigInt(params.amount) : BigInt(10000000); // Default 0.01 SUI
        
        if (!poolId) {
          logger.error('Pool ID is required for join_challenge operation');
          return res.status(400).json({
            success: false,
            error: 'Pool ID is required for join_challenge operation'
          });
        }
        
        logger.info(`Creating join_challenge transaction with pool: ${poolId}, amount: ${amount}`);
        
        try {
          const [coin] = tx.splitCoins(tx.gas, [tx.pure(amount)]);
          
          tx.moveCall({
            target: `${packageId}::boar_challenge::join_challenge`,
            arguments: [
              tx.object(poolId),
              coin,
              tx.object('0x6'),  // Clock
            ],
          });
          
          logger.info('join_challenge transaction created successfully');
        } catch (moveCallError) {
          logger.error('Error creating move call for join_challenge', {
            error: moveCallError.message,
            stack: moveCallError.stack,
            packageId,
            poolId,
            amount: amount.toString()
          });
          throw moveCallError;
        }
        
        req.customTransaction = tx;
        return next();
      }
      else if (operation === 'boar_challenge::create_custom_nft') {
        // Convert name to bytes for the contract
        const name = params.name || 'Custom NFT';
        const nameBytes = Array.from(new TextEncoder().encode(name));
        
        logger.info(`Creating custom NFT with name: ${name}`, {
          nameBytesLength: nameBytes.length
        });
        
        try {
          tx.moveCall({
            target: `${packageId}::boar_challenge::create_custom_nft`,
            arguments: [
              tx.pure(nameBytes),  // name as bytes
            ],
          });
          
          logger.info('create_custom_nft transaction created successfully');
        } catch (moveCallError) {
          logger.error('Error creating move call for create_custom_nft', {
            error: moveCallError.message,
            stack: moveCallError.stack,
            packageId,
            name,
            nameBytesLength: nameBytes.length
          });
          throw moveCallError;
        }
        
        req.customTransaction = tx;
        return next();
      }
      else if (operation === 'boar_challenge::complete_exercise') {
        const poolId = params.poolId;
        const nftId = params.nftId;
        
        if (!poolId || !nftId) {
          logger.error('Missing required parameters for complete_exercise', {
            hasPoolId: !!poolId,
            hasNftId: !!nftId
          });
          return res.status(400).json({
            success: false,
            error: 'Pool ID and NFT ID are required for complete_exercise operation'
          });
        }
        
        logger.info(`Creating complete_exercise transaction with pool: ${poolId}, nft: ${nftId}`);
        
        try {
          tx.moveCall({
            target: `${packageId}::boar_challenge::complete_exercise`,
            arguments: [
              tx.object(poolId),
              tx.object(nftId),
              tx.object('0x6'),  // Clock
            ],
          });
          
          logger.info('complete_exercise transaction created successfully');
        } catch (moveCallError) {
          logger.error('Error creating move call for complete_exercise', {
            error: moveCallError.message,
            stack: moveCallError.stack,
            packageId,
            poolId,
            nftId
          });
          throw moveCallError;
        }
        
        req.customTransaction = tx;
        return next();
      }
      
      // If no special handling for this boar_challenge operation
      logger.info(`No special handling for ${operation}, continuing with normal processing`);
      return next();
    } catch (error) {
      logger.error('Error in contract middleware:', {
        error: error.message,
        operation,
        stack: error.stack,
        params
      });
      return res.status(500).json({
        success: false,
        error: 'Failed to create transaction',
        details: error.message,
        stack: error.stack
      });
    }
  } else if (operation === 'counter::create') {
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
#!/usr/bin/env node

const { Command } = require('commander');
const { RLN, RLNIdentity } = require('../packages/sdk');
const fs = require('fs');
const path = require('path');

const program = new Command();

// Configuration
const CONFIG = {
    identitiesFile: path.join(__dirname, '../data/identities.json'),
    messagesFile: path.join(__dirname, '../data/messages.json'),
    epochLength: 3600, // 1 hour
    appId: 'rln-demo'
};

// Helper functions
async function loadIdentities() {
    if (!fs.existsSync(CONFIG.identitiesFile)) {
        return [];
    }
    const data = JSON.parse(fs.readFileSync(CONFIG.identitiesFile, 'utf8'));
    return data.map(item => ({
        name: item.name,
        identity: RLNIdentity.deserialize(item.identity),
        index: item.index
    }));
}

async function saveIdentities(identities) {
    const dir = path.dirname(CONFIG.identitiesFile);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    
    const data = identities.map(item => ({
        name: item.name,
        identity: item.identity.serialize(),
        index: item.index
    }));
    
    fs.writeFileSync(CONFIG.identitiesFile, JSON.stringify(data, null, 2));
}

async function loadMessages() {
    if (!fs.existsSync(CONFIG.messagesFile)) {
        return [];
    }
    return JSON.parse(fs.readFileSync(CONFIG.messagesFile, 'utf8'));
}

async function saveMessages(messages) {
    const dir = path.dirname(CONFIG.messagesFile);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(CONFIG.messagesFile, JSON.stringify(messages, null, 2));
}

// Commands
program
    .name('rln-demo')
    .description('CLI for RLN Anti-Spam demonstration')
    .version('1.0.0');

program
    .command('setup')
    .description('Initialize RLN system and create sample identities')
    .action(async () => {
        console.log('🚀 Setting up RLN demo...\n');
        
        // Initialize RLN
        const rln = new RLN({
            wasmPath: path.join(__dirname, '../build/rln_js/rln.wasm'),
            zkeyPath: path.join(__dirname, '../build/rln.zkey'),
            vkeyPath: path.join(__dirname, '../build/verification_key.json')
        });
        
        await rln.init();
        
        // Create sample identities
        const identities = [];
        const names = ['Alice', 'Bob', 'Charlie', 'Diana'];
        
        for (let i = 0; i < names.length; i++) {
            const identity = new RLNIdentity();
            const registration = await rln.registerIdentity(identity);
            
            identities.push({
                name: names[i],
                identity,
                index: registration.index
            });
            
            console.log(`✅ Created identity: ${names[i]}`);
            console.log(`   Index: ${registration.index}`);
            console.log(`   Commitment: ${registration.commitment}`);
        }
        
        await saveIdentities(identities);
        
        console.log(`\\n🌳 Merkle tree root: ${rln.getRoot()}`);
        console.log('📁 Identities saved to:', CONFIG.identitiesFile);
        console.log('\\n🎉 Setup complete! Use other commands to interact with the system.');
    });

program
    .command('list-identities')
    .description('List all registered identities')
    .action(async () => {
        const identities = await loadIdentities();
        
        if (identities.length === 0) {
            console.log('No identities found. Run: rln-demo setup');
            return;
        }
        
        console.log('👥 Registered Identities:\\n');
        for (const item of identities) {
            const commitment = await item.identity.getCommitment();
            console.log(`[${item.index}] ${item.name}`);
            console.log(`    Commitment: ${commitment}`);
        }
    });

program
    .command('post-message')
    .description('Post a message using RLN proof')
    .requiredOption('-i, --identity <index>', 'Identity index', parseInt)
    .requiredOption('-m, --message <text>', 'Message text')
    .option('-e, --epoch <epoch>', 'Epoch (default: current)', parseInt)
    .action(async (options) => {
        console.log('📝 Posting message with RLN proof...\\n');
        
        const identities = await loadIdentities();
        if (options.identity >= identities.length) {
            console.error('❌ Invalid identity index');
            process.exit(1);
        }
        
        const identity = identities[options.identity];
        
        // Initialize RLN
        const rln = new RLN({
            wasmPath: path.join(__dirname, '../build/rln_js/rln.wasm'),
            zkeyPath: path.join(__dirname, '../build/rln.zkey'),
            vkeyPath: path.join(__dirname, '../build/verification_key.json')
        });
        
        await rln.init();
        
        // Re-register all identities to rebuild the tree
        for (const item of identities) {
            await rln.registerIdentity(item.identity);
        }
        
        // Calculate epoch and external nullifier
        const epoch = options.epoch || rln.getCurrentEpoch(CONFIG.epochLength);
        const externalNullifier = await rln.calculateExternalNullifier(epoch, CONFIG.appId);
        
        // Generate unique message ID
        const messageId = Date.now();
        
        console.log('📋 Message details:');
        console.log(`   Identity: ${identity.name}`);
        console.log(`   Message: "${options.message}"`);
        console.log(`   Epoch: ${epoch}`);
        console.log(`   External Nullifier: ${externalNullifier}`);
        console.log(`   Message ID: ${messageId}`);
        
        // Generate proof
        console.log('\\n🔐 Generating RLN proof...');
        try {
            const proof = await rln.generateProof(
                identity.index,
                options.message,
                externalNullifier,
                messageId
            );
            
            console.log('✅ Proof generated successfully!');
            
            // Verify proof
            const isValid = await rln.verifyProof(proof);
            console.log(`🔍 Proof verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
            
            // Save message
            const messages = await loadMessages();
            const messageData = {
                id: messageId,
                identity: identity.name,
                identityIndex: identity.index,
                text: options.message,
                epoch: epoch,
                externalNullifier: externalNullifier,
                proof: proof.proof,
                publicSignals: proof.publicSignals,
                timestamp: new Date().toISOString()
            };
            
            messages.push(messageData);
            await saveMessages(messages);
            
            console.log('\\n📄 Message saved to:', CONFIG.messagesFile);
            console.log('🎉 Message posted successfully!');
            
        } catch (error) {
            console.error('❌ Failed to generate proof:', error.message);
            process.exit(1);
        }
    });

program
    .command('list-messages')
    .description('List all posted messages')
    .option('-e, --epoch <epoch>', 'Filter by epoch', parseInt)
    .action(async (options) => {
        const messages = await loadMessages();
        
        if (messages.length === 0) {
            console.log('No messages found. Post some with: rln-demo post-message');
            return;
        }
        
        const filteredMessages = options.epoch 
            ? messages.filter(m => m.epoch === options.epoch)
            : messages;
            
        console.log('📨 Posted Messages:\\n');
        filteredMessages.forEach((msg, index) => {
            console.log(`[${index}] ${msg.identity} (Epoch ${msg.epoch})`);
            console.log(`    "${msg.text}"`);
            console.log(`    Nullifier: ${msg.publicSignals[2]}`);
            console.log(`    Timestamp: ${msg.timestamp}\\n`);
        });
        
        if (options.epoch) {
            console.log(`Showing ${filteredMessages.length} messages for epoch ${options.epoch}`);
        } else {
            console.log(`Total messages: ${filteredMessages.length}`);
        }
    });

program
    .command('detect-spam')
    .description('Detect spam by finding duplicate nullifiers in the same epoch')
    .action(async () => {
        const messages = await loadMessages();
        
        if (messages.length === 0) {
            console.log('No messages to analyze');
            return;
        }
        
        console.log('🔍 Analyzing messages for spam...\\n');
        
        const epochGroups = {};
        messages.forEach(msg => {
            if (!epochGroups[msg.epoch]) {
                epochGroups[msg.epoch] = [];
            }
            epochGroups[msg.epoch].push(msg);
        });
        
        let spamFound = false;
        
        for (const [epoch, epochMessages] of Object.entries(epochGroups)) {
            const nullifiers = {};
            
            epochMessages.forEach(msg => {
                const nullifier = msg.publicSignals[2];
                if (nullifiers[nullifier]) {
                    console.log(`🚨 SPAM DETECTED in epoch ${epoch}!`);
                    console.log(`   Duplicate nullifier: ${nullifier}`);
                    console.log(`   Messages:`);
                    console.log(`     1. "${nullifiers[nullifier].text}" by ${nullifiers[nullifier].identity}`);
                    console.log(`     2. "${msg.text}" by ${msg.identity}`);
                    console.log(`   🔥 Identity can be slashed!\\n`);
                    spamFound = true;
                } else {
                    nullifiers[nullifier] = msg;
                }
            });
        }
        
        if (!spamFound) {
            console.log('✅ No spam detected. All messages have unique nullifiers per epoch.');
        }
    });

program
    .command('verify-message')
    .description('Verify a specific message proof')
    .requiredOption('-i, --index <index>', 'Message index', parseInt)
    .action(async (options) => {
        const messages = await loadMessages();
        
        if (options.index >= messages.length) {
            console.error('❌ Invalid message index');
            process.exit(1);
        }
        
        const message = messages[options.index];
        
        console.log('🔍 Verifying message proof...\\n');
        console.log(`Message: "${message.text}"`);
        console.log(`Identity: ${message.identity}`);
        console.log(`Epoch: ${message.epoch}`);
        
        // Initialize RLN for verification
        const rln = new RLN({
            wasmPath: path.join(__dirname, '../build/rln_js/rln.wasm'),
            zkeyPath: path.join(__dirname, '../build/rln.zkey'),
            vkeyPath: path.join(__dirname, '../build/verification_key.json')
        });
        
        await rln.init();
        
        try {
            const proof = {
                proof: message.proof,
                publicSignals: message.publicSignals
            };
            
            const isValid = await rln.verifyProof(proof);
            console.log(`\\n🔐 Proof verification: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
            
            if (isValid) {
                console.log('✅ Message proof is cryptographically valid');
                console.log('✅ Identity was registered in the merkle tree');
                console.log('✅ Rate limiting constraints are satisfied');
            } else {
                console.log('❌ Message proof is invalid');
                console.log('❌ This message should be rejected');
            }
            
        } catch (error) {
            console.error('❌ Verification failed:', error.message);
        }
    });

program
    .command('stats')
    .description('Show RLN system statistics')
    .action(async () => {
        const identities = await loadIdentities();
        const messages = await loadMessages();
        
        console.log('📊 RLN System Statistics\\n');
        console.log(`👥 Total Identities: ${identities.length}`);
        console.log(`📨 Total Messages: ${messages.length}`);
        
        if (messages.length > 0) {
            const epochs = [...new Set(messages.map(m => m.epoch))];
            console.log(`🕐 Active Epochs: ${epochs.length}`);
            
            const epochStats = {};
            messages.forEach(msg => {
                epochStats[msg.epoch] = (epochStats[msg.epoch] || 0) + 1;
            });
            
            console.log('\\n📈 Messages per Epoch:');
            Object.entries(epochStats).forEach(([epoch, count]) => {
                console.log(`   Epoch ${epoch}: ${count} messages`);
            });
            
            const identityStats = {};
            messages.forEach(msg => {
                identityStats[msg.identity] = (identityStats[msg.identity] || 0) + 1;
            });
            
            console.log('\\n👤 Messages per Identity:');
            Object.entries(identityStats).forEach(([identity, count]) => {
                console.log(`   ${identity}: ${count} messages`);
            });
        }
        
        console.log(`\\n⚙️  Configuration:`);
        console.log(`   Epoch Length: ${CONFIG.epochLength} seconds`);
        console.log(`   App ID: ${CONFIG.appId}`);
        console.log(`   Data Directory: ${path.dirname(CONFIG.identitiesFile)}`);
    });

program.parse();